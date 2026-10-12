package server

import (
	"bytes"
	"context"
	"errors"

	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
)

// The accounts table (PROTOCOL.md §6.5): account is the account id's
// bytes; sk 0x00 is the account's record, 0x01 ‖ addr a box it holds (the
// mirror of the box record's account), 0x04 ‖ id an adopt key's state. A box
// joins or leaves in one transaction over both tables, so the two sides
// never disagree.
const (
	skAccount  byte = 0x00
	skMember   byte = 0x01
	skAdoptKey byte = 0x04
)

func accountKey(id string, sk ...byte) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"account": bin([]byte(id)), "sk": bin(sk)}
}

func memberKey(id string, a protocol.Address) map[string]types.AttributeValue {
	return accountKey(id, append([]byte{skMember}, a[:]...)...)
}

func adoptKeyKey(id string, key [16]byte) map[string]types.AttributeValue {
	return accountKey(id, append([]byte{skAdoptKey}, key[:]...)...)
}

func accountItem(a *Account) map[string]types.AttributeValue {
	it := accountKey(a.ID, skAccount)
	it["unmetered"] = &types.AttributeValueMemberBOOL{Value: a.Unmetered}
	it["rev"] = num(a.Rev)
	return it
}

// accountRecord reads the key of an item of the accounts table: its account
// id, and whether it is the account's record.
func accountRecord(it item) (string, bool, error) {
	id, err := it.bytes("account")
	if err != nil {
		return "", false, err
	}
	sk, err := it.bytes("sk")
	if err != nil {
		return "", false, err
	}
	return string(id), bytes.Equal(sk, []byte{skAccount}), nil
}

func decodeAccount(it item) (*Account, error) {
	id, _, err := accountRecord(it)
	if err != nil {
		return nil, err
	}
	rev, err := it.uint("rev")
	if err != nil {
		return nil, err
	}
	u, ok := it["unmetered"].(*types.AttributeValueMemberBOOL)
	if !ok {
		return nil, errors.New("item: unmetered is missing or not a boolean")
	}
	return &Account{ID: id, Unmetered: u.Value, Rev: rev}, nil
}

// Account implements Store: the cache, or a strongly consistent read, so a
// change made before it is in it (one made after reaches the cache by the
// stream).
func (s *DynamoStore) Account(ctx context.Context, id string) (*Account, error) {
	if a, ok := s.accCache.get(id); ok {
		return a, nil
	}
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.accts, Key: accountKey(id, skAccount), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	a, err := decodeAccount(out.Item)
	if err != nil {
		return nil, err
	}
	s.accCache.put(a)
	return a, nil
}

// CreateAccount implements Store.
func (s *DynamoStore) CreateAccount(ctx context.Context, a *Account) error {
	a.Rev = 1
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                &s.accts,
		Item:                     accountItem(a),
		ConditionExpression:      aws.String("attribute_not_exists(#a)"),
		ExpressionAttributeNames: map[string]string{"#a": "account"},
	})
	if _, ok := isConditionFailed(err); ok {
		return ErrExists
	}
	return err
}

// PutAdoptKey implements Store. Its expiry is also the item's TTL.
func (s *DynamoStore) PutAdoptKey(ctx context.Context, k *AdoptKey) error {
	it := adoptKeyKey(k.Account, k.ID)
	it["uses"] = num(uint64(k.Uses)) //nolint:gosec // uses are not negative
	it["expires"] = num(ms(k.Expires))
	it["expires_at"] = num(ttlSeconds(ms(k.Expires)))
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                &s.accts,
		Item:                     it,
		ConditionExpression:      aws.String("attribute_not_exists(#a)"),
		ExpressionAttributeNames: map[string]string{"#a": "account"},
	})
	if _, ok := isConditionFailed(err); ok {
		return ErrExists
	}
	return err
}

// boxRevCheck is the update of a box record at b.Rev that bumps it.
func boxRevCheck(b *Box, expr string, names map[string]string, values map[string]types.AttributeValue) *types.Update {
	names["#rev"] = "rev"
	values[":old"], values[":new"] = num(b.Rev), num(b.Rev+1)
	return &types.Update{
		Key:                       boxKey(b.Addr),
		UpdateExpression:          aws.String(expr),
		ConditionExpression:       aws.String("#rev = :old"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	}
}

// Adopt implements Store: in one transaction, the box record names the
// account, the account holds the box, the key loses a use, and the box's
// old account, if any, lets it go.
func (s *DynamoStore) Adopt(ctx context.Context, b *Box, account string, key [16]byte) error {
	upd := boxRevCheck(b, "SET #acct = :acct, #rev = :new", map[string]string{"#acct": "account"}, map[string]types.AttributeValue{":acct": bin([]byte(account))})
	upd.TableName = &s.boxes
	items := []types.TransactWriteItem{
		{Update: upd},
		{Put: &types.Put{TableName: &s.accts, Item: memberKey(account, b.Addr)}},
		{Update: &types.Update{
			TableName:                 &s.accts,
			Key:                       adoptKeyKey(account, key),
			UpdateExpression:          aws.String("SET #u = #u - :one"),
			ConditionExpression:       aws.String("#u >= :one AND #e > :now"),
			ExpressionAttributeNames:  map[string]string{"#u": "uses", "#e": "expires"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":one": num(1), ":now": num(s.nowMs())},
		}},
	}
	if b.Account != "" {
		items = append(items, types.TransactWriteItem{Delete: &types.Delete{TableName: &s.accts, Key: memberKey(b.Account, b.Addr)}})
	}
	if err := s.transact(ctx, b, items, map[int]error{0: ErrStale, 2: ErrKeyRefused}); err != nil {
		return err
	}
	b.Account, b.Rev = account, b.Rev+1
	s.applyBox(b)
	return nil
}

// Leave implements Store: in one transaction, the box record names no
// account and the account no longer holds the box.
func (s *DynamoStore) Leave(ctx context.Context, b *Box) error {
	upd := boxRevCheck(b, "REMOVE #acct SET #rev = :new", map[string]string{"#acct": "account"}, map[string]types.AttributeValue{})
	upd.TableName = &s.boxes
	items := []types.TransactWriteItem{
		{Update: upd},
		{Delete: &types.Delete{TableName: &s.accts, Key: memberKey(b.Account, b.Addr)}},
	}
	if err := s.transact(ctx, b, items, map[int]error{0: ErrStale}); err != nil {
		return err
	}
	b.Account, b.Rev = "", b.Rev+1
	s.applyBox(b)
	return nil
}

// transact writes items in one transaction. A condition that failed is the
// error named for its item; a failed box condition also evicts the box's
// cached record, which may be the stale one.
func (s *DynamoStore) transact(ctx context.Context, b *Box, items []types.TransactWriteItem, failed map[int]error) error {
	_, err := s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	var tc *types.TransactionCanceledException
	if !errors.As(err, &tc) {
		return err
	}
	for i, r := range tc.CancellationReasons {
		if aws.ToString(r.Code) != "ConditionalCheckFailed" {
			continue
		}
		if e, ok := failed[i]; ok {
			if errors.Is(e, ErrStale) {
				s.cache.evict(b.Addr)
			}
			return e
		}
	}
	return err
}

// applyAccountRecord applies one record of the -accounts-table stream to the
// account cache. Only an account's record counts.
func (s *DynamoStore) applyAccountRecord(r stypes.Record) {
	if r.Dynamodb == nil {
		return
	}
	if r.EventName == stypes.OperationTypeRemove {
		id, rec, err := accountRecord(fromStream(r.Dynamodb.Keys))
		if err != nil {
			s.logf("accounts: skipping a removal: %v", err)
			return
		}
		if rec {
			s.accCache.evict(id)
		}
		return
	}
	it := fromStream(r.Dynamodb.NewImage)
	id, rec, err := accountRecord(it)
	if err != nil {
		s.logf("accounts: skipping an item: %v", err)
		return
	}
	if !rec {
		return
	}
	rev, err := it.uint("rev")
	if err != nil {
		s.logf("accounts: skipping an account record: %v", err)
		return
	}
	s.accCache.refresh(id, rev, func() (*Account, error) { return decodeAccount(it) })
}
