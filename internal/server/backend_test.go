package server

// The store's backends, and the boundary between them and memory: the
// injector of faults at it, which every test of what memory makes of a
// write's outcome or of a read's answer uses, and the stream's records as
// the DynamoDB backend hands them to memory.

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
)

// dynamo is the DynamoDB backend s is over.
func (s *Memory) dynamo() *dynamoBackend { return s.backend.(*dynamoBackend) }

// onDynamo is the store as memory over the DynamoDB backend, if it is.
func onDynamo(st Store) (*Memory, bool) {
	s, ok := st.(*Memory)
	if !ok {
		return nil, false
	}
	_, ok = s.backend.(*dynamoBackend)
	return s, ok
}

// applyBoxRecord applies a record of the -boxes-table stream as the
// DynamoDB backend's feed hands it to memory.
func (s *Memory) applyBoxRecord(r stypes.Record) { s.applyStream(boxStreamChange(r)) }

// applyMsgRecord is applyBoxRecord for the -msgs-table stream.
func (s *Memory) applyMsgRecord(r stypes.Record) { s.applyStream(msgStreamChange(r)) }

// applyAccountRecord is applyBoxRecord for the -accounts-table stream.
func (s *Memory) applyAccountRecord(r stypes.Record) { s.applyStream(accountStreamChange(r)) }

func (s *Memory) applyStream(c Change, err error) {
	if err == nil && c.Kind != 0 {
		s.apply(c)
	}
}

// applyBoxImage applies an item of the -boxes-table table as it now is, as
// the stream's image of it.
func (s *Memory) applyBoxImage(it item) {
	s.applyBoxRecord(stypes.Record{EventName: stypes.OperationTypeModify, Dynamodb: &stypes.StreamRecord{NewImage: toStream(it)}})
}

// toStream is an item as a stream's image carries it.
func toStream(it item) map[string]stypes.AttributeValue {
	out := map[string]stypes.AttributeValue{}
	for k, v := range it {
		if c := toStreamAV(v); c != nil {
			out[k] = c
		}
	}
	return out
}

// toStreamAV is fromStream's convertAV, the other way.
func toStreamAV(v types.AttributeValue) stypes.AttributeValue {
	switch v := v.(type) {
	case *types.AttributeValueMemberB:
		return &stypes.AttributeValueMemberB{Value: v.Value}
	case *types.AttributeValueMemberS:
		return &stypes.AttributeValueMemberS{Value: v.Value}
	case *types.AttributeValueMemberN:
		return &stypes.AttributeValueMemberN{Value: v.Value}
	case *types.AttributeValueMemberBOOL:
		return &stypes.AttributeValueMemberBOOL{Value: v.Value}
	case *types.AttributeValueMemberL:
		l := make([]stypes.AttributeValue, 0, len(v.Value))
		for _, e := range v.Value {
			if c := toStreamAV(e); c != nil {
				l = append(l, c)
			}
		}
		return &stypes.AttributeValueMemberL{Value: l}
	case *types.AttributeValueMemberM:
		return &stypes.AttributeValueMemberM{Value: toStream(v.Value)}
	}
	return nil
}

// fault is what the injector makes of a write: its outcome, as Backend
// names them.
type fault int

const (
	asIs          fault = iota
	refusedBefore       // refused, with the write's own refusal, nothing applied
	unknownBefore       // an error the backend states nothing of, nothing applied
	unknownAfter        // applied, then an error the backend states nothing of
)

func (f fault) String() string {
	return [...]string{"as is", "refused", "unknown before applying", "unknown after applying"}[f]
}

// errInjected is the injector's error of no kind.
var errInjected = errors.New("injected: an error the backend states nothing of")

// errStated is a refusal AWS stated, for a write with no condition of its
// own: a throttle, or an answer of 4xx to the call.
var errStated = refused(errors.New("AWS throttled the call"))

// faults wraps a backend, and makes any write's outcome what a test asks of
// it, and runs a hook at a read's answer: after the backend answered, before
// memory has the answer. It stands where every fault of a backend reaches
// memory (IronGall-dev/irongall-client#407 item 4).
type faults struct {
	Backend
	mu     sync.Mutex
	writes map[string]fault // by the Backend method's name
	refuse map[string]error // the refusal a write states, if not its own
	// read, if set, runs at each read's answer, with the method's name.
	read func(method string)
}

// injectFaults puts an injector between s and its backend.
func injectFaults(s *Memory) *faults {
	f := &faults{Backend: s.backend, writes: map[string]fault{}, refuse: map[string]error{}}
	s.backend = f
	return f
}

// set makes method's outcome f, until set again.
func (f *faults) set(method string, x fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes[method] = x
}

// ownRefusal is the refusal each write states of itself.
var ownRefusal = map[string]error{
	"CreateBox":     ErrExists,
	"UpdateBox":     ErrStale,
	"DeleteBox":     errStated,
	"Revoke":        ErrStale,
	"Adopt":         ErrStale,
	"Leave":         ErrStale,
	"CreateAccount": ErrExists,
	"PutAdoptKey":   ErrExists,
	"PutMessage":    errNotStored,
	"Retire":        ErrNotFound,
	"DeleteMessage": ErrNotFound,
	"DeleteFrom":    errStated,
}

// write runs do as method's fault says.
func (f *faults) write(method string, do func() error) error {
	f.mu.Lock()
	x, ref := f.writes[method], f.refuse[method]
	f.mu.Unlock()
	if ref == nil {
		ref = ownRefusal[method]
	}
	switch x {
	case refusedBefore:
		return ref
	case unknownBefore:
		return errInjected
	case unknownAfter:
		if err := do(); err != nil {
			return err
		}
		return errInjected
	}
	return do()
}

// answered runs the read hook at method's answer.
func (f *faults) answered(method string) {
	f.mu.Lock()
	h := f.read
	f.mu.Unlock()
	if h != nil {
		h(method)
	}
}

func (f *faults) ReadAddress(ctx context.Context, a protocol.Address) (*Box, *Revocations, error) {
	b, rv, err := f.Backend.ReadAddress(ctx, a)
	f.answered("ReadAddress")
	return b, rv, err
}

func (f *faults) ReadLive(ctx context.Context, box protocol.Address) ([]Header, error) {
	hs, err := f.Backend.ReadLive(ctx, box)
	f.answered("ReadLive")
	return hs, err
}

func (f *faults) List(ctx context.Context, box protocol.Address, after *Cursor, limit int) ([]Header, error) {
	hs, err := f.Backend.List(ctx, box, after, limit)
	f.answered("List")
	return hs, err
}

func (f *faults) Message(ctx context.Context, box protocol.Address, id [32]byte, from int64) (*Header, []byte, error) {
	h, body, err := f.Backend.Message(ctx, box, id, from)
	f.answered("Message")
	return h, body, err
}

func (f *faults) Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	h, err := f.Backend.Dedupe(ctx, box, id)
	f.answered("Dedupe")
	return h, err
}

func (f *faults) Account(ctx context.Context, id string) (*Account, error) {
	a, err := f.Backend.Account(ctx, id)
	f.answered("Account")
	return a, err
}

func (f *faults) AdoptKey(ctx context.Context, account string, hash [32]byte) (*AdoptKey, error) {
	k, err := f.Backend.AdoptKey(ctx, account, hash)
	f.answered("AdoptKey")
	return k, err
}

func (f *faults) CreateBox(ctx context.Context, b *Box) error {
	return f.write("CreateBox", func() error { return f.Backend.CreateBox(ctx, b) })
}

func (f *faults) UpdateBox(ctx context.Context, b *Box) error {
	return f.write("UpdateBox", func() error { return f.Backend.UpdateBox(ctx, b) })
}

func (f *faults) DeleteBox(ctx context.Context, a protocol.Address) error {
	return f.write("DeleteBox", func() error { return f.Backend.DeleteBox(ctx, a) })
}

func (f *faults) Revoke(ctx context.Context, a protocol.Address, rv *Revocations) (*Revocations, error) {
	var held *Revocations
	err := f.write("Revoke", func() (err error) {
		held, err = f.Backend.Revoke(ctx, a, rv)
		return err
	})
	return held, err
}

func (f *faults) Adopt(ctx context.Context, b *Box, account string, key [32]byte) error {
	return f.write("Adopt", func() error { return f.Backend.Adopt(ctx, b, account, key) })
}

func (f *faults) Leave(ctx context.Context, b *Box) error {
	return f.write("Leave", func() error { return f.Backend.Leave(ctx, b) })
}

func (f *faults) CreateAccount(ctx context.Context, a *Account) error {
	return f.write("CreateAccount", func() error { return f.Backend.CreateAccount(ctx, a) })
}

func (f *faults) PutAdoptKey(ctx context.Context, k *AdoptKey) error {
	return f.write("PutAdoptKey", func() error { return f.Backend.PutAdoptKey(ctx, k) })
}

func (f *faults) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) error {
	return f.write("PutMessage", func() error { return f.Backend.PutMessage(ctx, box, h, body) })
}

func (f *faults) Retire(ctx context.Context, box protocol.Address, id [32]byte) (time.Time, error) {
	var at time.Time
	err := f.write("Retire", func() (err error) {
		at, err = f.Backend.Retire(ctx, box, id)
		return err
	})
	return at, err
}

func (f *faults) DeleteMessage(ctx context.Context, box protocol.Address, id [32]byte) (time.Time, error) {
	var at time.Time
	err := f.write("DeleteMessage", func() (err error) {
		at, err = f.Backend.DeleteMessage(ctx, box, id)
		return err
	})
	return at, err
}

func (f *faults) DeleteFrom(ctx context.Context, box protocol.Address, from func(protocol.Address) bool, retired func([32]byte, time.Time)) error {
	return f.write("DeleteFrom", func() error { return f.Backend.DeleteFrom(ctx, box, from, retired) })
}
