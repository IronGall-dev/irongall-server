package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// DynamoStore is the production store (PROTOCOL-SERVER.md §7): box records in one
// DynamoDB table, messages in another (each item its header and its dedupe
// record), accounts in a third, bodies in an S3 Express One Zone directory
// bucket. What a poll needs lives in memory (index), loaded per box on its
// first use, and bounded caches of box and account records serve sends
// (recCache). This process's own writes and each table's stream (feed) keep
// all three current.
//
// A send writes the body, then the message item; an ack deletes the body,
// then takes the item out of the list. Neither pair is atomic, and neither
// needs to be: each step is safe to repeat.
type DynamoStore struct {
	db     *dynamodb.Client
	s3     *s3.Client
	boxes  string // -boxes-table
	msgs   string // -msgs-table
	accts  string // -accounts-table
	bucket string
	now    func() time.Time
	log    *log.Logger

	// consistent makes every read strongly consistent; otherwise only a
	// box's load into memory is (DynamoConfig.ConsistentReads).
	consistent bool
	// loads counts boxes read into memory, for tests.
	loads atomic.Int64

	idx      *index
	cache    *boxCache
	misses   *missCache // boxes a read found missing
	accCache *accountCache
	boxFeed  *feed // the -boxes-table stream: the box cache and standing
	msgFeed  *feed // the -msgs-table stream: layer 1's marks
	accFeed  *feed // the -accounts-table stream: the account cache
	fatal    func(error)
	ready    atomic.Bool

	// fault, in tests, fails a write sequence at a named point, as a crash
	// there would leave it.
	fault func(point string) error
}

// DynamoConfig configures a DynamoStore.
type DynamoConfig struct {
	AWS                                          aws.Config
	BoxesTable, MsgsTable, AccountsTable, Bucket string
	Now                                          func() time.Time // time.Now if nil
	// BoxCache is how many box records memory holds, as many account
	// records, and as many boxes remembered as missing; 0: none.
	BoxCache       int
	StreamInterval time.Duration // how often each stream shard is read
	Log            *log.Logger   // nil: no log
	// ConsistentReads makes every read strongly consistent, at twice the
	// read units: for tests, which read back what they wrote within
	// milliseconds. Otherwise only a box's load into memory is: a strongly
	// consistent read costs twice the read units, and polls are the load. A
	// stale read elsewhere costs a retry or one poll; the conditional writes
	// keep the data right.
	ConsistentReads bool
	// Fatal is called if a stream follower loses its place in its stream.
	// Memory can no longer be shown current; the process must restart, which
	// rebuilds it from the tables.
	Fatal func(error)
}

// NewDynamoStore returns a store that is not ready until Start returns.
func NewDynamoStore(c DynamoConfig) *DynamoStore {
	s := &DynamoStore{
		db:         dynamodb.NewFromConfig(c.AWS),
		s3:         s3.NewFromConfig(c.AWS),
		boxes:      c.BoxesTable,
		msgs:       c.MsgsTable,
		accts:      c.AccountsTable,
		bucket:     c.Bucket,
		now:        c.Now,
		log:        c.Log,
		consistent: c.ConsistentReads,
		idx:        newIndex(),
		cache:      newBoxCache(c.BoxCache),
		misses:     newMissCache(c.BoxCache),
		accCache:   newAccountCache(c.BoxCache),
		fatal:      c.Fatal,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if c.StreamInterval <= 0 {
		c.StreamInterval = time.Second
	}
	streams := dynamodbstreams.NewFromConfig(c.AWS)
	newFeed := func(apply func(stypes.Record)) *feed {
		return &feed{streams: streams, interval: c.StreamInterval, apply: apply, logf: s.logf, shards: map[string]*shard{}}
	}
	s.boxFeed, s.msgFeed, s.accFeed = newFeed(s.applyBoxRecord), newFeed(s.applyMsgRecord), newFeed(s.applyAccountRecord)
	return s
}

func (s *DynamoStore) logf(format string, args ...any) {
	if s.log != nil {
		s.log.Printf(format, args...)
	}
}

// Start positions a follower on every open shard of the three streams, then
// returns; the streams are followed until ctx ends. Memory starts empty, and
// a box is loaded on its first use, after the positioning: a change made
// before its load is in the load, one made after reaches memory by a stream,
// or both, and applying it twice is harmless (ARCHITECTURE.md § Startup).
// Nothing is kept across restarts.
func (s *DynamoStore) Start(ctx context.Context) error {
	feeds := []struct {
		f     *feed
		table string
	}{{s.boxFeed, s.boxes}, {s.msgFeed, s.msgs}, {s.accFeed, s.accts}}
	for _, x := range feeds {
		arn, err := streamARN(ctx, s.db, x.table)
		if err != nil {
			return err
		}
		if err := x.f.position(ctx, arn); err != nil {
			return err
		}
	}
	lostPlace := func(err error) {
		s.ready.Store(false)
		if s.fatal != nil {
			s.fatal(err)
		}
	}
	for _, x := range feeds {
		go x.f.run(ctx, lostPlace)
	}
	s.ready.Store(true)
	return nil
}

// Ready reports whether the three streams are followed.
func (s *DynamoStore) Ready() bool { return s.ready.Load() }

// Keys. Every key is binary. Boxes: addr is the box's address, sk 0x00 its
// record; the box's own items will sit under other sk values. Messages: box
// and id, and while the message is unacked, live = received_at (ms, u64
// big-endian) ‖ id, the sort key of the sparse index that lists a box's
// unacked mail oldest first.
const (
	skBox     byte = 0x00
	liveIndex      = "live"
)

var ttlMs = uint64(protocol.TTL / time.Millisecond)

func ms(t time.Time) uint64     { return uint64(t.UnixMilli()) }          //nolint:gosec // times after 1970
func fromMs(v uint64) time.Time { return time.UnixMilli(int64(v)).UTC() } //nolint:gosec // decoded from our own keys

func (s *DynamoStore) nowMs() uint64 { return ms(s.now()) }

// ttlSeconds is the TTL attribute: DynamoDB deletes the item some time after
// it, so reads judge expiry from received_at.
func ttlSeconds(expMs uint64) uint64 { return (expMs + 999) / 1000 }

func boxKey(a protocol.Address) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"addr": bin(a[:]), "sk": bin([]byte{skBox})}
}

func msgKey(box protocol.Address, id [32]byte) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"box": bin(box[:]), "id": bin(id[:])}
}

func liveKey(receivedMs uint64, id [32]byte) []byte {
	k := binary.BigEndian.AppendUint64(make([]byte, 0, 40), receivedMs)
	return append(k, id[:]...)
}

// fromLiveKey reads received_at in ms, and the id, from a live key.
func fromLiveKey(k []byte) (uint64, [32]byte, error) {
	var id [32]byte
	if len(k) != 40 {
		return 0, id, errors.New("item: not a live key")
	}
	copy(id[:], k[8:])
	return binary.BigEndian.Uint64(k[:8]), id, nil
}

func bodyKey(box protocol.Address, id [32]byte) string { return box.String() + "/" + hexID(id) }

func bin(b []byte) types.AttributeValue { return &types.AttributeValueMemberB{Value: b} }
func num(v uint64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatUint(v, 10)}
}
func str(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

// item is a DynamoDB item, read with checks.
type item map[string]types.AttributeValue

func (it item) bytes(name string) ([]byte, error) {
	if v, ok := it[name].(*types.AttributeValueMemberB); ok {
		return v.Value, nil
	}
	return nil, fmt.Errorf("item: %s is missing or not binary", name)
}

// hash reads a 32-byte binary attribute: an address or an id.
func (it item) hash(name string) ([32]byte, error) {
	var h [32]byte
	b, err := it.bytes(name)
	if err != nil {
		return h, err
	}
	if len(b) != len(h) {
		return h, fmt.Errorf("item: %s is not 32 bytes", name)
	}
	copy(h[:], b)
	return h, nil
}

func (it item) uint(name string) (uint64, error) {
	if v, ok := it[name].(*types.AttributeValueMemberN); ok {
		return strconv.ParseUint(v.Value, 10, 64)
	}
	return 0, fmt.Errorf("item: %s is missing or not a number", name)
}

func (it item) string(name string) (string, error) {
	if v, ok := it[name].(*types.AttributeValueMemberS); ok {
		return v.Value, nil
	}
	return "", fmt.Errorf("item: %s is missing or not a string", name)
}

// boxRecord reads the key of an item of the -boxes-table table: its address, and
// whether it is the box's record.
func boxRecord(it item) (protocol.Address, bool, error) {
	a, err := it.hash("addr")
	if err != nil {
		return a, false, err
	}
	sk, err := it.bytes("sk")
	if err != nil {
		return a, false, err
	}
	return a, bytes.Equal(sk, []byte{skBox}), nil
}

// The box record.

// boxState is every attribute of a box record that can change.
func boxState(b *Box) map[string]types.AttributeValue {
	retired := make([]types.AttributeValue, 0, len(b.Retired))
	for _, r := range b.Retired {
		retired = append(retired, &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
			"type":      str(string(r.Type)),
			"not_after": num(ms(r.NotAfter)),
			"key_hash":  bin(r.KeyHash[:]),
		}})
	}
	return map[string]types.AttributeValue{
		"state":         str(string(b.State)),
		"statement":     bin(b.Statement),
		"statement_sig": bin(b.Signature),
		"retired":       &types.AttributeValueMemberL{Value: retired},
		"epoch":         num(uint64(b.Epoch)),
		"rev":           num(b.Rev),
	}
}

func boxItem(b *Box) map[string]types.AttributeValue {
	it := boxKey(b.Addr)
	it["identity"] = bin(b.Identity)
	it["created"] = num(ms(b.Created))
	for k, v := range boxState(b) {
		it[k] = v
	}
	return it
}

func decodeStanding(it item) (Standing, uint64, error) {
	state, err := it.string("state")
	if err != nil {
		return Standing{}, 0, err
	}
	epoch, err := it.uint("epoch")
	if err != nil || epoch > 1<<32-1 {
		return Standing{}, 0, fmt.Errorf("item: bad epoch: %v", err)
	}
	rev, err := it.uint("rev")
	if err != nil {
		return Standing{}, 0, err
	}
	return Standing{State: State(state), Epoch: uint32(epoch)}, rev, nil
}

func decodeBox(it item) (*Box, error) {
	a, err := it.hash("addr")
	if err != nil {
		return nil, err
	}
	st, rev, err := decodeStanding(it)
	if err != nil {
		return nil, err
	}
	b := &Box{Addr: a, State: st.State, Epoch: st.Epoch, Rev: rev}
	if b.Identity, err = it.bytes("identity"); err != nil {
		return nil, err
	}
	if _, ok := it["account"]; ok {
		acc, err := it.bytes("account")
		if err != nil {
			return nil, err
		}
		b.Account = string(acc)
	}
	if b.Statement, err = it.bytes("statement"); err != nil {
		return nil, err
	}
	if b.Signature, err = it.bytes("statement_sig"); err != nil {
		return nil, err
	}
	created, err := it.uint("created")
	if err != nil {
		return nil, err
	}
	b.Created = fromMs(created)
	if b.Prekey, err = protocol.ParsePrekey(b.Statement); err != nil {
		return nil, fmt.Errorf("item: the stored prekey: %w", err)
	}
	l, ok := it["retired"].(*types.AttributeValueMemberL)
	if !ok {
		return nil, errors.New("item: retired is missing or not a list")
	}
	for _, v := range l.Value {
		m, ok := v.(*types.AttributeValueMemberM)
		if !ok {
			return nil, errors.New("item: a retired prekey is not a map")
		}
		r := item(m.Value)
		t, err := r.string("type")
		if err != nil {
			return nil, err
		}
		notAfter, err := r.uint("not_after")
		if err != nil {
			return nil, err
		}
		h, err := r.bytes("key_hash")
		if err != nil || len(h) != 32 {
			return nil, errors.New("item: bad key_hash")
		}
		ret := Retired{Type: protocol.KeyType(t), NotAfter: fromMs(notAfter)}
		copy(ret.KeyHash[:], h)
		b.Retired = append(b.Retired, ret)
	}
	return b, nil
}

// Message items.

// msgItem is a new message's item: its header, its dedupe record, and its
// entry in the live index.
func msgItem(box protocol.Address, h *Header) map[string]types.AttributeValue {
	recv := ms(h.ReceivedAt)
	it := msgKey(box, h.ID)
	it["from"] = bin(h.From[:])
	it["size"] = num(uint64(h.Size)) //nolint:gosec // a size is not negative
	it["sig"] = bin(h.Signature)
	it["received_at"] = num(recv)
	it["expires_at"] = num(ttlSeconds(recv + ttlMs))
	it["live"] = bin(liveKey(recv, h.ID))
	return it
}

// decodeMsg reads a message item, and whether it is still in the list
// (unacked). Expiry is the caller's to judge.
func decodeMsg(it item) (*Header, bool, error) {
	id, err := it.hash("id")
	if err != nil {
		return nil, false, err
	}
	from, err := it.hash("from")
	if err != nil {
		return nil, false, err
	}
	recv, err := it.uint("received_at")
	if err != nil {
		return nil, false, err
	}
	size, err := it.uint("size")
	if err != nil {
		return nil, false, err
	}
	h := &Header{ID: id, From: from, Size: int(size), ReceivedAt: fromMs(recv), ExpiresAt: fromMs(recv + ttlMs)} //nolint:gosec // sizes are small
	if sig, err := it.bytes("sig"); err == nil {
		h.Signature = sig
	}
	_, live := it["live"]
	return h, live, nil
}

// decodeLive reads an entry of the live index: the key, from and size.
func decodeLive(it item) (*Header, error) {
	k, err := it.bytes("live")
	if err != nil {
		return nil, err
	}
	recv, id, err := fromLiveKey(k)
	if err != nil {
		return nil, err
	}
	from, err := it.hash("from")
	if err != nil {
		return nil, err
	}
	size, err := it.uint("size")
	if err != nil {
		return nil, err
	}
	return &Header{ID: id, From: from, Size: int(size), ReceivedAt: fromMs(recv), ExpiresAt: fromMs(recv + ttlMs)}, nil //nolint:gosec // sizes are small
}

func (s *DynamoStore) failAt(point string) error {
	if s.fault == nil {
		return nil
	}
	return s.fault(point)
}

func isConditionFailed(err error) (*types.ConditionalCheckFailedException, bool) {
	var ccf *types.ConditionalCheckFailedException
	return ccf, errors.As(err, &ccf)
}

func isNoSuchKey(err error) bool {
	var nsk *s3types.NoSuchKey
	var nf *s3types.NotFound
	return errors.As(err, &nsk) || errors.As(err, &nf)
}

// IsThrottle reports whether err is AWS refusing for capacity: a throttle,
// or the SDK's own retry quota running out.
func IsThrottle(err error) bool {
	var q ratelimit.QuotaExceededError
	if errors.As(err, &q) {
		return true
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		_, ok := retry.DefaultThrottleErrorCodes[api.ErrorCode()]
		return ok
	}
	return false
}

// loadTimeout bounds a box's load into memory, which callers share: it runs
// apart from the request that started it.
const loadTimeout = 10 * time.Second

// ensure loads box a into memory on its first use by this process.
func (s *DynamoStore) ensure(ctx context.Context, a protocol.Address) error {
	return s.idx.ensure(ctx, a, func() (boxRead, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loadTimeout)
		defer cancel()
		return s.readBox(ctx, a)
	})
}

// readBox reads what memory holds of a box: its record's standing and its
// live messages, strongly consistent, so a change made before the read is in
// it (one made after reaches memory by a stream). The record joins the cache.
func (s *DynamoStore) readBox(ctx context.Context, a protocol.Address) (boxRead, error) {
	s.loads.Add(1)
	var r boxRead
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.boxes, Key: boxKey(a), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return r, err
	}
	if out.Item == nil {
		return r, nil // no box: no mail either
	}
	b, err := decodeBox(out.Item)
	if err != nil {
		return r, err
	}
	s.cache.put(b)
	r.exists, r.st, r.rev = true, Standing{State: b.State, Epoch: b.Epoch}, b.Rev
	p := dynamodb.NewQueryPaginator(s.db, s.liveQuery(a, s.liveFrom(), true))
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return r, err
		}
		for _, it := range out.Items {
			h, err := decodeLive(it)
			if err != nil {
				return r, err
			}
			r.marks = append(r.marks, newMark(h.ID, h.From, ms(h.ReceivedAt)+ttlMs))
		}
	}
	return r, nil
}

// liveFrom is the lowest live key at now: received_at > now − TTL, so an
// expired message the TTL has not yet deleted is never read.
func (s *DynamoStore) liveFrom() []byte { return liveKey(s.nowMs()-ttlMs+1, [32]byte{}) }

// liveQuery is a Query of a box's entries in the live index from lo.
func (s *DynamoStore) liveQuery(box protocol.Address, lo []byte, consistent bool) *dynamodb.QueryInput {
	return &dynamodb.QueryInput{
		TableName:                 &s.msgs,
		IndexName:                 aws.String(liveIndex),
		KeyConditionExpression:    aws.String("#b = :b AND #l BETWEEN :lo AND :hi"),
		ProjectionExpression:      aws.String("#l, #f, #s"),
		ExpressionAttributeNames:  map[string]string{"#b": "box", "#l": "live", "#f": "from", "#s": "size"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":b": bin(box[:]), ":lo": bin(lo), ":hi": bin(bytes.Repeat([]byte{0xff}, 40))},
		ConsistentRead:            aws.Bool(consistent),
	}
}

// Standing implements Store: from memory, after the box's load on its first
// use.
func (s *DynamoStore) Standing(ctx context.Context, a protocol.Address) (Standing, error) {
	if err := s.ensure(ctx, a); err != nil {
		return Standing{}, err
	}
	st, ok := s.idx.standing(a)
	if !ok {
		return Standing{}, ErrNotFound
	}
	return st, nil
}

// applyBox records a box this process wrote.
func (s *DynamoStore) applyBox(b *Box) {
	s.misses.wrote(b.Addr)
	s.cache.put(b)
	s.idx.setStanding(b.Addr, Standing{State: b.State, Epoch: b.Epoch}, b.Rev)
}

// Box implements Store: the cache, or a read. A box the read does not find is
// remembered as missing for a while (missCache), so naming it again costs no
// read.
func (s *DynamoStore) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	if b, ok := s.cache.get(a); ok {
		return b, nil
	}
	missing, seq := s.misses.has(a, s.now())
	if missing {
		return nil, ErrNotFound
	}
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.boxes, Key: boxKey(a), ConsistentRead: aws.Bool(s.consistent)})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		s.misses.missed(a, seq, s.now())
		return nil, ErrNotFound
	}
	b, err := decodeBox(out.Item)
	if err != nil {
		return nil, err
	}
	s.cache.put(b)
	return b, nil
}

// Known implements Store: the record cache, or the memory of a box a read did
// not find.
func (s *DynamoStore) Known(a protocol.Address) (*Box, bool) {
	if b, ok := s.cache.get(a); ok {
		return b, true
	}
	missing, _ := s.misses.has(a, s.now())
	return nil, missing
}

// CreateBox implements Store.
func (s *DynamoStore) CreateBox(ctx context.Context, b *Box) error {
	b.Rev = 1
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                &s.boxes,
		Item:                     boxItem(b),
		ConditionExpression:      aws.String("attribute_not_exists(#a)"),
		ExpressionAttributeNames: map[string]string{"#a": "addr"},
	})
	if _, ok := isConditionFailed(err); ok {
		s.misses.wrote(b.Addr) // it has a record, whoever wrote it
		return ErrExists
	}
	if err != nil {
		return err
	}
	s.applyBox(b)
	return nil
}

// UpdateBox implements Store: every attribute that can change, if the record
// is still at b.Rev. Attributes it does not name are left alone.
func (s *DynamoStore) UpdateBox(ctx context.Context, b *Box) error {
	next := cloneBox(b)
	next.Rev = b.Rev + 1
	names := map[string]string{}
	values := map[string]types.AttributeValue{":old": num(b.Rev)}
	var sets []string
	for k, v := range boxState(next) {
		names["#"+k] = k
		values[":"+k] = v
		sets = append(sets, "#"+k+" = :"+k)
	}
	slices.Sort(sets)
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.boxes,
		Key:                       boxKey(b.Addr),
		UpdateExpression:          aws.String("SET " + strings.Join(sets, ", ")),
		ConditionExpression:       aws.String("#rev = :old"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	})
	if _, ok := isConditionFailed(err); ok {
		s.cache.evict(b.Addr) // the cached record may be the stale one
		return ErrStale
	}
	if err != nil {
		return err
	}
	b.Rev = next.Rev
	s.applyBox(b)
	return nil
}

// getMsg reads a message's item, acked or not; ErrNotFound if there is none
// or it has expired.
func (s *DynamoStore) getMsg(ctx context.Context, box protocol.Address, id [32]byte) (*Header, bool, error) {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.msgs, Key: msgKey(box, id), ConsistentRead: aws.Bool(s.consistent)})
	if err != nil {
		return nil, false, err
	}
	if out.Item == nil {
		return nil, false, ErrNotFound
	}
	h, live, err := decodeMsg(out.Item)
	if err != nil {
		return nil, false, err
	}
	if ms(h.ExpiresAt) <= s.nowMs() {
		return nil, false, ErrNotFound // expired; the TTL deletes it later
	}
	return h, live, nil
}

// Dedupe implements Store: the message's item, acked or not. A stale miss is
// caught by PutMessage's conditional write.
func (s *DynamoStore) Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	h, _, err := s.getMsg(ctx, box, id)
	return h, err
}

// PutMessage implements Store (PROTOCOL-SERVER.md §7): the body, then the item, if
// no live one has this id. A crash after the body leaves an orphan the
// lifecycle rule reaps, and the retry writes both again.
func (s *DynamoStore) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	if _, err := s.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket,
		Key:    aws.String(bodyKey(box, h.ID)),
		Body:   bytes.NewReader(body),
	}); err != nil {
		return nil, err
	}
	if err := s.failAt("put: after the body"); err != nil {
		return nil, err
	}
	now := s.nowMs()
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                           &s.msgs,
		Item:                                msgItem(box, h),
		ConditionExpression:                 aws.String("attribute_not_exists(#id) OR #r <= :cutoff"),
		ExpressionAttributeNames:            map[string]string{"#id": "id", "#r": "received_at"},
		ExpressionAttributeValues:           map[string]types.AttributeValue{":cutoff": num(now - ttlMs)},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if ccf, ok := isConditionFailed(err); ok {
		orig, _, err := decodeMsg(ccf.Item) // a concurrent send of the same ciphertext
		return orig, err
	}
	if err != nil {
		return nil, err
	}
	s.idx.insert(box, newMark(h.ID, h.From, ms(h.ReceivedAt)+ttlMs), now)
	return nil, nil
}

// retire takes a live message out of the list, and out of memory: its item
// stays as the dedupe record until it expires. ErrNotFound if it is not live.
func (s *DynamoStore) retire(ctx context.Context, box protocol.Address, id [32]byte) error {
	now := s.nowMs()
	out, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.msgs,
		Key:                       msgKey(box, id),
		UpdateExpression:          aws.String("REMOVE #l, #sig"),
		ConditionExpression:       aws.String("attribute_exists(#l) AND #r > :cutoff"),
		ExpressionAttributeNames:  map[string]string{"#l": "live", "#sig": "sig", "#r": "received_at"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":cutoff": num(now - ttlMs)},
		ReturnValues:              types.ReturnValueUpdatedOld,
	})
	if _, ok := isConditionFailed(err); ok {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	k, err := item(out.Attributes).bytes("live")
	if err != nil {
		return err
	}
	recv, _, err := fromLiveKey(k)
	if err != nil {
		return err
	}
	s.idx.remove(box, prefix8(id[:]), recv+ttlMs, now, false)
	return nil
}

func (s *DynamoStore) deleteBody(ctx context.Context, box protocol.Address, id [32]byte) error {
	_, err := s.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: aws.String(bodyKey(box, id))})
	if err != nil && !isNoSuchKey(err) {
		return err
	}
	return nil
}

// Message implements Store. A live message whose body is gone (a
// half-finished ack, or a body the lifecycle rule took early) is retired and
// answered as gone.
func (s *DynamoStore) Message(ctx context.Context, box protocol.Address, id [32]byte) (*Header, []byte, error) {
	h, live, err := s.getMsg(ctx, box, id)
	if err != nil {
		return nil, nil, err
	}
	if !live {
		return nil, nil, ErrNotFound
	}
	out, err := s.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: aws.String(bodyKey(box, id))})
	if isNoSuchKey(err) {
		if err := s.retire(ctx, box, id); err != nil && !errors.Is(err, ErrNotFound) {
			return nil, nil, err
		}
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, nil, err
	}
	return h, body, nil
}

// DeleteMessage implements Store (ack): the body, then the item leaves the
// list. Both steps are safe to repeat, so a crash between them is finished by
// the client's next ack, and a fetch in between finds no body and retires it.
func (s *DynamoStore) DeleteMessage(ctx context.Context, box protocol.Address, id [32]byte) error {
	if err := s.deleteBody(ctx, box, id); err != nil {
		return err
	}
	if err := s.failAt("ack: after the body"); err != nil {
		return err
	}
	return s.retire(ctx, box, id)
}

// DeleteMessages implements Store (close): every live message in the box, as
// acks: bodies first, then each item leaves the list.
func (s *DynamoStore) DeleteMessages(ctx context.Context, box protocol.Address) error {
	var ids [][32]byte
	p := dynamodb.NewQueryPaginator(s.db, s.liveQuery(box, s.liveFrom(), s.consistent))
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, it := range out.Items {
			k, err := item(it).bytes("live")
			if err != nil {
				return err
			}
			_, id, err := fromLiveKey(k)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
	}
	for chunk := range slices.Chunk(ids, 1000) {
		objs := make([]s3types.ObjectIdentifier, 0, len(chunk))
		for _, id := range chunk {
			objs = append(objs, s3types.ObjectIdentifier{Key: aws.String(bodyKey(box, id))})
		}
		out, err := s.s3.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &s.bucket, Delete: &s3types.Delete{Objects: objs, Quiet: aws.Bool(true)}})
		if err != nil {
			return err
		}
		if len(out.Errors) > 0 {
			return fmt.Errorf("deleting bodies: %s", aws.ToString(out.Errors[0].Message))
		}
	}
	for _, id := range ids {
		if err := s.retire(ctx, box, id); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}

// List implements Store: a Query of the live index over its live key range.
// A page read just after a write may miss it while memory's count has it;
// the Go client saves an ETag only for an empty box, so it lists again at
// its next poll.
func (s *DynamoStore) List(ctx context.Context, box protocol.Address, after *Cursor, limit int) ([]Header, error) {
	lo := s.liveFrom()
	in := s.liveQuery(box, lo, s.consistent)
	if after != nil {
		if start := liveKey(ms(after.ReceivedAt), after.ID); bytes.Compare(start, lo) >= 0 {
			k := msgKey(box, after.ID)
			k["live"] = bin(start)
			in.ExclusiveStartKey = k
		}
	}
	var hs []Header
	for len(hs) < limit {
		in.Limit = aws.Int32(int32(limit - len(hs))) //nolint:gosec // a page is small
		out, err := s.db.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range out.Items {
			h, err := decodeLive(it)
			if err != nil {
				return nil, err
			}
			hs = append(hs, *h)
		}
		if out.LastEvaluatedKey == nil {
			break
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
	return hs, nil
}

// Count implements Store: from memory, after the box's load on its first
// use.
func (s *DynamoStore) Count(ctx context.Context, box protocol.Address) (int, uint64, error) {
	if err := s.ensure(ctx, box); err != nil {
		return 0, 0, err
	}
	n, v := s.idx.count(box, s.nowMs())
	return n, v, nil
}

// PairCount implements Store: from memory, after the box's load on its
// first use.
func (s *DynamoStore) PairCount(ctx context.Context, box, from protocol.Address) (int, time.Time, error) {
	if err := s.ensure(ctx, box); err != nil {
		return 0, time.Time{}, err
	}
	n, oldest := s.idx.pair(box, prefix8(from[:]), s.nowMs())
	if n == 0 {
		return 0, time.Time{}, nil
	}
	return n, fromMs(oldest), nil
}

// After implements Store: from memory, after the box's load on its first use.
func (s *DynamoStore) After(ctx context.Context, box protocol.Address, c *Cursor) (int, error) {
	if err := s.ensure(ctx, box); err != nil {
		return 0, err
	}
	return s.idx.after(box, ms(c.ReceivedAt)+ttlMs, prefix8(c.ID[:]), s.nowMs()), nil
}

// Holds implements Store: from memory, after the box's load on its first use.
// A message another process stored is held once the stream has brought it.
func (s *DynamoStore) Holds(ctx context.Context, box protocol.Address, id [32]byte) (bool, error) {
	if err := s.ensure(ctx, box); err != nil {
		return false, err
	}
	return s.idx.holds(box, prefix8(id[:]), s.nowMs()), nil
}

// Fetched implements Store, from memory as Holds does.
func (s *DynamoStore) Fetched(ctx context.Context, box protocol.Address, id [32]byte) (held, again bool, err error) {
	if err := s.ensure(ctx, box); err != nil {
		return false, false, err
	}
	held, again = s.idx.fetched(box, prefix8(id[:]), s.nowMs())
	return held, again, nil
}

// applyBoxImage applies an item of the -boxes-table table as it now is, from the
// stream. Only a box's record counts; its other items are not memory's.
func (s *DynamoStore) applyBoxImage(it item) {
	a, rec, err := boxRecord(it)
	if err != nil {
		s.logf("boxes: skipping an item: %v", err)
		return
	}
	if !rec {
		return
	}
	st, rev, err := decodeStanding(it)
	if err != nil {
		s.logf("boxes: skipping a box record: %v", err)
		return
	}
	s.misses.wrote(a)
	s.idx.setStanding(a, st, rev)
	s.cache.refresh(a, rev, func() (*Box, error) { return decodeBox(it) })
}

// applyBoxRemoval applies a deleted item's key, from the stream.
func (s *DynamoStore) applyBoxRemoval(key item) {
	a, rec, err := boxRecord(key)
	if err != nil {
		s.logf("boxes: skipping a removal: %v", err)
		return
	}
	if rec {
		s.idx.dropStanding(a)
		s.cache.evict(a)
	}
}

// applyMsgImage applies a message item as it now is, from the stream: in the
// list, a mark; out of it (acked, or its body gone), none.
func (s *DynamoStore) applyMsgImage(it item) {
	box, err := it.hash("box")
	if err != nil {
		s.logf("msgs: skipping an item: %v", err)
		return
	}
	h, live, err := decodeMsg(it)
	if err != nil {
		s.logf("msgs: skipping an item: %v", err)
		return
	}
	exp := ms(h.ReceivedAt) + ttlMs
	if live {
		s.idx.insert(box, newMark(h.ID, h.From, exp), s.nowMs())
		return
	}
	s.idx.remove(box, prefix8(h.ID[:]), exp, s.nowMs(), true)
}
