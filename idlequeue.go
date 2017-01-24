package mokumokuren

import (
	"sync"
	"time"
)

type idleQueueNode struct {
	newer, older *idleQueueNode
	time         time.Time
	key          FlowKey
}

// An idle queue associates flow keys with the time of the
// last packet seen, and allows quick access to the least recently active flow.

type IdleQueue struct {
	newest, oldest *idleQueueNode
	node           map[FlowKey]*idleQueueNode
	lock           sync.RWMutex
}

// Create a new idle queue.
func NewIdleQueue() *IdleQueue {
	q := new(IdleQueue)
	q.node = make(map[FlowKey]*idleQueueNode)
	return q
}

func (q *IdleQueue) Tick(k FlowKey, t time.Time) {

	if n, ok := q.node[k]; ok {
		// remove node from present location in queue
		n.newer.older = n.older
		n.older.newer = n.newer

		// update its time, maintaining monotonic invariant
		if t.After(q.newest.time) {
			n.time = t
		} else {
			n.time = q.newest.time
		}

		// and stitch it to the front
		n.older = q.newest
		n.older.newer = n
		n.newer = nil
		q.newest = n
	} else {
		// new node. create and stitch to the front
		n = new(idleQueueNode)
		n.time = t
		n.key = k
		n.older = q.newest
		n.older.newer = n
		q.newest = n
	}
}

// Remove and return the next

func (q *IdleQueue) NextIdleBefore(t time.Time) (k FlowKey, ok bool) {
	if q.oldest != nil && q.oldest.time.Before(t) {
		n := q.oldest
		q.oldest = q.oldest.newer
		if q.oldest != nil {
			q.oldest.older = nil
		}
		return n.key, true
	} else {
		return FlowKey{}, false
	}
}

// Get the time associated with the least recently active flow.
func (q *IdleQueue) OldestFlowTime() time.Time {
	if q.oldest != nil {
		return q.oldest.time
	} else {
		return time.Unix(0, 0)
	}
}
