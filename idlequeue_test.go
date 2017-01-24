package mokumokuren

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"testing"
)

var BASE_TIME time.Time

func TestIdleQueue(r *testing.T) {
	basetime := time.Parse("2006-01-02 15:04:05 -0700", "2009-02-20 15:00:00 +0000")
	endtime := basetime // add something to the basetime to get a reasonable endtime

	flowtimes := []struct {
		k           FlowKey
		t           time.Time
		should_idle bool
	}{}

	should_idle := make(map[FlowKey]bool)

	for _, ft := range flowtimes {
		should_idle[ft.k] = ft.should_idle
	}

	q := NewIdleQueue()

	for _, ft := range flowtimes {
		q.Tick(ft.k, ft.t)
	}

	for {
		k, ok := q.NextIdleBefore(endtime)
		if !ok {
			break
		}
		if !should_idle[k] {
			t.Errorf("flow key %v idled unexpectedly", k)
		}
		delete(should_idle, k)
	}

	for k := range should_idle {
		if should_idle[k] {
			t.Errorf("flow key %v failed to idle", k)
		}
	}

}
