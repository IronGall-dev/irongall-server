package server

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
)

// The accounts table (PROTOCOL.md §6.5): account is the account id's
// bytes; sk 0x00 is the account's record and 0x04 ‖ SHA-256 of the key an
// adopt key's state.
// Which boxes an account holds is the box records' to say: each names its
// account, and the boxes table's sparse index on it lists an account's
// boxes, so a box that leaves, or that DynamoDB's TTL takes, leaves nothing
// behind here.
const (
	skAccount  byte = 0x00
	skAdoptKey byte = 0x04
)

func accountKey(id string, sk ...byte) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"account": bin([]byte(id)), "sk": bin(sk)}
}

func adoptKeyKey(id string, hash [32]byte) map[string]types.AttributeValue {
	return accountKey(id, append([]byte{skAdoptKey}, hash[:]...)...)
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
// stream, or, where it was counted after the read's token, keeps the fill
// out: recCache.fill).
func (s *DynamoStore) Account(ctx context.Context, id string) (*Account, error) {
	if a, ok := s.accCache.get(id); ok {
		return a, nil
	}
	tok := s.accCache.begin(id)
	ctx, cancel := bounded(ctx)
	defer cancel()
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.accts, Key: accountKey(id, skAccount), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return nil, err
	}
	if err := s.failAt("account: after the read"); err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	a, err := decodeAccount(out.Item)
	if err != nil {
		return nil, err
	}
	s.accCache.fill(a, tok)
	return a, nil
}

// CreateAccount implements Store.
func (s *DynamoStore) CreateAccount(ctx context.Context, a *Account) error {
	a.Rev = 1
	ctx, cancel := bounded(ctx)
	defer cancel()
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
	it := adoptKeyKey(k.Account, k.Hash)
	it["uses"] = num(uint64(k.Uses)) //nolint:gosec // uses are not negative
	it["expires"] = num(ms(k.Expires))
	it["expires_at"] = num(ttlSeconds(ms(k.Expires)))
	ctx, cancel := bounded(ctx)
	defer cancel()
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

// AdoptKey implements Store.
func (s *DynamoStore) AdoptKey(ctx context.Context, account string, hash [32]byte) (*AdoptKey, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.accts, Key: adoptKeyKey(account, hash), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	it := item(out.Item)
	uses, err := it.uint("uses")
	if err != nil {
		return nil, err
	}
	exp, err := it.uint("expires")
	if err != nil {
		return nil, err
	}
	return &AdoptKey{Account: account, Hash: hash, Uses: int(uses), Expires: fromMs(exp)}, nil //nolint:gosec // uses are a count we wrote
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
// account, and the key loses a use.
func (s *DynamoStore) Adopt(ctx context.Context, b *Box, account string, key [32]byte) error {
	upd := boxRevCheck(b, "SET #acct = :acct, #rev = :new", map[string]string{"#acct": "account"}, map[string]types.AttributeValue{":acct": bin([]byte(account))})
	upd.TableName = &s.boxes
	items := []types.TransactWriteItem{
		{Update: upd},
		{Update: &types.Update{
			TableName:                 &s.accts,
			Key:                       adoptKeyKey(account, key),
			UpdateExpression:          aws.String("SET #u = #u - :one"),
			ConditionExpression:       aws.String("#u >= :one AND #e > :now"),
			ExpressionAttributeNames:  map[string]string{"#u": "uses", "#e": "expires"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":one": num(1), ":now": num(s.nowMs())},
		}},
	}
	if err := s.transact(ctx, b, items, map[int]error{0: ErrStale, 1: ErrKeyRefused}); err != nil {
		return err
	}
	b.Account, b.Rev = account, b.Rev+1
	s.applyBox(b)
	return nil
}

// Leave implements Store: the box record names no account.
func (s *DynamoStore) Leave(ctx context.Context, b *Box) error {
	upd := boxRevCheck(b, "REMOVE #acct SET #rev = :new", map[string]string{"#acct": "account"}, map[string]types.AttributeValue{})
	ctx, cancel := bounded(ctx)
	defer cancel()
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.boxes,
		Key:                       upd.Key,
		UpdateExpression:          upd.UpdateExpression,
		ConditionExpression:       upd.ConditionExpression,
		ExpressionAttributeNames:  upd.ExpressionAttributeNames,
		ExpressionAttributeValues: upd.ExpressionAttributeValues,
	})
	if _, ok := isConditionFailed(err); ok || isTransactionConflict(err) {
		s.cache.evict(b.Addr) // the cached record may be the stale one
		return ErrStale
	}
	if err != nil {
		return err
	}
	b.Account, b.Rev = "", b.Rev+1
	s.applyBox(b)
	return nil
}

// A transaction that meets another on one of its items is cancelled for a
// TransactionConflict, which the SDK does not retry (AWS, "Transaction
// conflict handling in DynamoDB"). It applied nothing and DynamoDB checks
// every condition again, so it is sent again as it is: by a new call, which
// carries a new client token. The tries and pauses are the SDK's own for
// DynamoDB under its newer retry behaviour (AWS_NEW_RETRIES_2026): four in
// all, each pause a random share of 25 ms, doubled after each try.
const (
	transactTries = 4
	transactPause = 25 * time.Millisecond
)

// transact writes items in one transaction. A condition that failed is the
// error named for its item, whatever else met another; a failed box
// condition also evicts the box's cached record, which may be the stale one.
// A conflict that lasts every try is ErrStale, and evicts it too.
func (s *DynamoStore) transact(ctx context.Context, b *Box, items []types.TransactWriteItem, failed map[int]error) error {
	for try := 1; ; try++ {
		call, cancel := bounded(ctx)
		_, err := s.db.TransactWriteItems(call, &dynamodb.TransactWriteItemsInput{TransactItems: items})
		cancel()
		var tc *types.TransactionCanceledException
		if !errors.As(err, &tc) {
			return err
		}
		conflict := false
		for i, r := range tc.CancellationReasons {
			switch aws.ToString(r.Code) {
			case "ConditionalCheckFailed":
				if e, ok := failed[i]; ok {
					if errors.Is(e, ErrStale) {
						s.cache.evict(b.Addr)
					}
					return e
				}
			case "TransactionConflict":
				conflict = true
			}
		}
		if !conflict {
			return err
		}
		if try == transactTries {
			s.cache.evict(b.Addr)
			return ErrStale
		}
		pause := time.NewTimer(rand.N(transactPause << (try - 1))) //nolint:gosec // a pause's jitter, no secret
		select {
		case <-pause.C:
		case <-ctx.Done():
			pause.Stop()
			return ctx.Err()
		}
	}
}

// isTransactionConflict reports whether err is a write of one item that met a
// transaction on it, which the SDK does not retry either. The item changes if
// that transaction commits, so the write is answered as a failed condition.
func isTransactionConflict(err error) bool {
	var tc *types.TransactionConflictException
	return errors.As(err, &tc)
}

// applyAccountRecord applies one record of the -accounts-table stream to the
// account cache, as a write (recCache.write). Only an account's record
// counts.
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
			s.accCache.write(id, evicted[*Account])
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
		// Counted all the same, so a read begun before it puts nothing; what
		// is held stays.
		s.accCache.write(id, func(cur *Account, held, _ bool) (*Account, bool) { return cur, held })
		return
	}
	s.accCache.write(id, s.accCache.image(rev, func() (*Account, error) { return decodeAccount(it) }))
}
