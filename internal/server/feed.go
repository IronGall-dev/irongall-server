package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
)

// feed follows one table's DynamoDB stream: every shard, each parent before
// its children (AWS docs, DynamoDB Streams, reading and processing a stream),
// applying each change to the process's memory. It keeps no position across
// restarts: a restart rebuilds memory from the tables and follows the streams
// from then on.
type feed struct {
	streams  streamsAPI
	interval time.Duration
	apply    func(stypes.Record)
	logf     func(format string, args ...any)

	// Read by the follower's goroutine only, once position has returned.
	arn    string
	shards map[string]*shard
	listed time.Time // the last full listing of shards
	ended  bool      // a shard ended since: list again for its children
}

// streamsAPI is the part of the DynamoDB Streams client the follower uses.
type streamsAPI interface {
	DescribeStream(context.Context, *dynamodbstreams.DescribeStreamInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.DescribeStreamOutput, error)
	GetShardIterator(context.Context, *dynamodbstreams.GetShardIteratorInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetShardIteratorOutput, error)
	GetRecords(context.Context, *dynamodbstreams.GetRecordsInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetRecordsOutput, error)
}

type shard struct {
	id, parent string
	iter       *string
	seq        string // the last sequence number applied
	latest     bool   // positioned at LATEST at startup, nothing read since
	done       bool   // read to its end, or closed before startup
}

// relistEvery is how often the follower lists every shard, to find ones it
// was not told about when their parent ended.
const relistEvery = time.Minute

// errLost is a follower that can no longer show it saw every change: it fell
// more than the stream's 24 hours behind, an iterator expired before it read
// anything, or the stream is gone.
type errLost struct{ err error }

func (e *errLost) Error() string { return "stream: lost its place: " + e.err.Error() }
func (e *errLost) Unwrap() error { return e.err }

func lost(err error) bool {
	var t *stypes.TrimmedDataAccessException
	var nf *stypes.ResourceNotFoundException
	return errors.As(err, &t) || errors.As(err, &nf)
}

// streamARN returns a table's stream, which must carry new images.
func streamARN(ctx context.Context, db *dynamodb.Client, table string) (string, error) {
	t, err := db.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &table})
	if err != nil {
		return "", err
	}
	if t.Table.LatestStreamArn == nil || t.Table.StreamSpecification == nil || !aws.ToBool(t.Table.StreamSpecification.StreamEnabled) {
		return "", fmt.Errorf("table %s has no stream", table)
	}
	if v := t.Table.StreamSpecification.StreamViewType; v != types.StreamViewTypeNewImage && v != types.StreamViewTypeNewAndOldImages {
		return "", fmt.Errorf("table %s: the stream must carry new images, not %s", table, v)
	}
	return *t.Table.LatestStreamArn, nil
}

// position puts an iterator at LATEST on every open shard of the stream. A
// closed shard holds only changes from before the load, which the load
// covers.
func (f *feed) position(ctx context.Context, arn string) error {
	f.arn = arn
	all, err := f.list(ctx)
	if err != nil {
		return err
	}
	for _, s := range all {
		sh := &shard{id: aws.ToString(s.ShardId), parent: aws.ToString(s.ParentShardId)}
		if s.SequenceNumberRange != nil && s.SequenceNumberRange.EndingSequenceNumber != nil {
			sh.done = true
		} else {
			out, err := f.streams.GetShardIterator(ctx, &dynamodbstreams.GetShardIteratorInput{
				StreamArn: &f.arn, ShardId: s.ShardId, ShardIteratorType: stypes.ShardIteratorTypeLatest,
			})
			if err != nil {
				return err
			}
			sh.iter, sh.latest = out.ShardIterator, true
		}
		f.shards[sh.id] = sh
	}
	f.listed = time.Now()
	return nil
}

func (f *feed) list(ctx context.Context) ([]stypes.Shard, error) {
	var all []stypes.Shard
	in := &dynamodbstreams.DescribeStreamInput{StreamArn: &f.arn}
	for {
		out, err := f.streams.DescribeStream(ctx, in)
		if err != nil {
			return nil, err
		}
		all = append(all, out.StreamDescription.Shards...)
		if out.StreamDescription.LastEvaluatedShardId == nil {
			return all, nil
		}
		in.ExclusiveStartShardId = out.StreamDescription.LastEvaluatedShardId
	}
}

// run reads every shard each interval until ctx ends, or the follower loses
// its place, which it reports to fatal.
func (f *feed) run(ctx context.Context, fatal func(error)) {
	t := time.NewTicker(f.interval)
	defer t.Stop()
	for {
		if err := f.pass(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			var l *errLost
			if errors.As(err, &l) {
				fatal(err)
				return
			}
			f.logf("stream: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pass reads each shard whose parent is done, from where it left off.
func (f *feed) pass(ctx context.Context) error {
	if f.ended || time.Since(f.listed) > relistEvery {
		if err := f.relist(ctx); err != nil {
			if lost(err) {
				return &errLost{err}
			}
			return err
		}
	}
	ids := make([]string, 0, len(f.shards))
	for id := range f.shards {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		sh := f.shards[id]
		if sh.done {
			continue
		}
		if p, ok := f.shards[sh.parent]; ok && !p.done {
			continue // a child waits for its parent
		}
		if err := f.read(ctx, sh); err != nil {
			return err
		}
	}
	return nil
}

// relist adds shards not seen before, read from their start, and forgets
// finished ones the stream no longer lists.
func (f *feed) relist(ctx context.Context) error {
	all, err := f.list(ctx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range all {
		id := aws.ToString(s.ShardId)
		seen[id] = true
		if _, ok := f.shards[id]; !ok {
			f.shards[id] = &shard{id: id, parent: aws.ToString(s.ParentShardId)}
		}
	}
	for id, sh := range f.shards {
		if !seen[id] && sh.done {
			delete(f.shards, id)
		}
	}
	f.listed, f.ended = time.Now(), false
	return nil
}

// read drains a shard as far as it goes now.
func (f *feed) read(ctx context.Context, sh *shard) error {
	if sh.iter == nil {
		in := &dynamodbstreams.GetShardIteratorInput{StreamArn: &f.arn, ShardId: &sh.id}
		switch {
		case sh.seq != "":
			in.ShardIteratorType, in.SequenceNumber = stypes.ShardIteratorTypeAfterSequenceNumber, aws.String(sh.seq)
		case sh.latest:
			return &errLost{fmt.Errorf("the iterator for shard %s expired before anything was read", sh.id)}
		default:
			in.ShardIteratorType = stypes.ShardIteratorTypeTrimHorizon
		}
		out, err := f.streams.GetShardIterator(ctx, in)
		if lost(err) {
			return &errLost{err}
		}
		if err != nil {
			return err
		}
		if sh.iter = out.ShardIterator; sh.iter == nil {
			sh.done, f.ended = true, true
			return nil
		}
	}
	for {
		out, err := f.streams.GetRecords(ctx, &dynamodbstreams.GetRecordsInput{ShardIterator: sh.iter, Limit: aws.Int32(1000)})
		var expired *stypes.ExpiredIteratorException
		if errors.As(err, &expired) {
			sh.iter = nil // re-positioned after the last record, next pass
			return nil
		}
		if lost(err) {
			return &errLost{err}
		}
		if err != nil {
			return err
		}
		for _, r := range out.Records {
			f.apply(r)
			if r.Dynamodb != nil && r.Dynamodb.SequenceNumber != nil {
				sh.seq, sh.latest = *r.Dynamodb.SequenceNumber, false
			}
		}
		if sh.iter = out.NextShardIterator; sh.iter == nil {
			sh.done, f.ended = true, true
			return nil
		}
		if len(out.Records) == 0 {
			return nil
		}
	}
}

// applyBoxRecord applies one record of the -boxes-table stream to memory.
func (s *DynamoStore) applyBoxRecord(r stypes.Record) {
	if r.Dynamodb == nil {
		return
	}
	if r.EventName == stypes.OperationTypeRemove {
		s.applyBoxRemoval(fromStream(r.Dynamodb.Keys))
		return
	}
	s.applyBoxImage(fromStream(r.Dynamodb.NewImage))
}

// applyMsgRecord applies one record of the -msgs-table stream to memory. A
// removal is ignored: nothing deletes a message item but the TTL,
// after the message expired, and memory drops a mark at its expiry.
func (s *DynamoStore) applyMsgRecord(r stypes.Record) {
	if r.Dynamodb == nil || r.EventName == stypes.OperationTypeRemove {
		return
	}
	s.applyMsgImage(fromStream(r.Dynamodb.NewImage))
}

// fromStream converts a stream image to the DynamoDB client's types: the two
// SDK packages declare the same shapes separately.
func fromStream(m map[string]stypes.AttributeValue) item {
	out := make(item, len(m))
	for k, v := range m {
		if c := convertAV(v); c != nil {
			out[k] = c
		}
	}
	return out
}

func convertAV(v stypes.AttributeValue) types.AttributeValue {
	switch v := v.(type) {
	case *stypes.AttributeValueMemberB:
		return &types.AttributeValueMemberB{Value: v.Value}
	case *stypes.AttributeValueMemberS:
		return &types.AttributeValueMemberS{Value: v.Value}
	case *stypes.AttributeValueMemberN:
		return &types.AttributeValueMemberN{Value: v.Value}
	case *stypes.AttributeValueMemberBOOL:
		return &types.AttributeValueMemberBOOL{Value: v.Value}
	case *stypes.AttributeValueMemberNULL:
		return &types.AttributeValueMemberNULL{Value: v.Value}
	case *stypes.AttributeValueMemberBS:
		return &types.AttributeValueMemberBS{Value: v.Value}
	case *stypes.AttributeValueMemberSS:
		return &types.AttributeValueMemberSS{Value: v.Value}
	case *stypes.AttributeValueMemberNS:
		return &types.AttributeValueMemberNS{Value: v.Value}
	case *stypes.AttributeValueMemberL:
		l := make([]types.AttributeValue, 0, len(v.Value))
		for _, e := range v.Value {
			if c := convertAV(e); c != nil {
				l = append(l, c)
			}
		}
		return &types.AttributeValueMemberL{Value: l}
	case *stypes.AttributeValueMemberM:
		return &types.AttributeValueMemberM{Value: fromStream(v.Value)}
	}
	return nil
}
