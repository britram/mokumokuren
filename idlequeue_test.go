package mokumokuren_test

import (
	"testing"
	"time"

	moku "github.com/britram/mokumokuren"
	"github.com/google/gopacket/layers"
)

var BASE_TIME time.Time

func TestIdleQueue(t *testing.T) {
	basetime, _ := time.Parse("2006-01-02 15:04:05 -0700", "2009-02-20 15:00:00 +0000")
	endtime := basetime.Add(34 * time.Second)

	flowtimes := []struct {
		k           moku.FlowKey
		t           time.Time
		should_idle bool
	}{
		{moku.FlowKey{"2001:db8::31", "2001:db8::32", 32769, 443, uint8(layers.IPProtocolTCP)}, basetime.Add(30 * time.Second), true},
		{moku.FlowKey{"192.0.2.31", "192.0.2.32", 32770, 443, uint8(layers.IPProtocolUDP)}, basetime.Add(31 * time.Second), true},
		{moku.FlowKey{"2001:db8::31", "2001:db8::32", 32771, 80, uint8(layers.IPProtocolTCP)}, basetime.Add(32 * time.Second), true},
		{moku.FlowKey{"192.0.2.31", "192.0.2.32", 32772, 443, uint8(layers.IPProtocolTCP)}, basetime.Add(33 * time.Second), true},
		{moku.FlowKey{"2001:db8::31", "2001:db8::32", 32769, 443, uint8(layers.IPProtocolTCP)}, basetime.Add(35 * time.Second), false},
		{moku.FlowKey{"192.0.2.31", "192.0.2.32", 32772, 443, uint8(layers.IPProtocolTCP)}, basetime.Add(36 * time.Second), false},
		{moku.FlowKey{"2001:db8::31", "2001:db8::32", 32771, 80, uint8(layers.IPProtocolTCP)}, basetime.Add(37 * time.Second), false},
		{moku.FlowKey{"192.0.2.31", "192.0.2.32", 32770, 443, uint8(layers.IPProtocolUDP)}, basetime.Add(39 * time.Second), false},
	}

	should_idle := make(map[moku.FlowKey]bool)

	for _, ft := range flowtimes {
		should_idle[ft.k] = ft.should_idle
	}

	q := moku.NewIdleQueue()

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
