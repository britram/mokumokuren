package mokumokuren

import (
	"github.com/google/gopacket"
	"time"
)

type idleQueueNode struct {
	newer, older *idleQueueNode
	time         time.Time
	key          gopacket.Flow
}

type IdleQueue struct {
	newest, oldest *idleQueueNode
	node           map[gopacket.Flow]*idleQueueNode
}

func NewIdleQueue() *IdleQueue {
	q := new(IdleQueue)
	q.node = make(map[gopacket.Flow]*idleQueueNode)
	return q
}

func (q *IdleQueue) Tick(k gopacket.Flow, t time.Time) {

	if n, ok := q.node[k]; ok {
		// remove node from present location in queue
		n.newer.older = n.older
		n.older.newer = n.newer

		// update its time
		n.time = t

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

func (q *IdleQueue) NextIdleBefore(t time.Time) (f gopacket.Flow, ok bool) {
	if q.oldest != nil && q.oldest.time.Before(t) {
		q.oldest = q.oldest.newer
		if q.oldest != nil {
			q.oldest.older = nil
		}
		return f, true
	} else {
		return gopacket.Flow{}, false
	}
}

func (q *IdleQueue) OldestFlowTime() time.Time {
	if q.oldest != nil {
		return q.oldest.time
	} else {
		return time.Unix(0, 0)
	}
}
