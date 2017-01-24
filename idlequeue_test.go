package mokumokuren

import (
	"github.com/google/gopacket/layers"
	"net"
	"testing"
	"time"
)

var BASE_TIME time.Time

func TestIdleQueue(t *testing.T) {
	basetime, _ := time.Parse("2006-01-02 15:04:05 -0700", "2009-02-20 15:00:00 +0000")
	endtime := basetime.Add(34 * time.Second)

	flowtimes := []struct {
		k           FlowKey
		t           time.Time
		should_idle bool
	}{
		{NewFlowKey(net.ParseIP("2001:db8::31"), net.ParseIP("2001:db8::32"), 32769, 443, layers.IPProtocolTCP),
			basetime.Add(30 * time.Second), true},
		{NewFlowKey(net.ParseIP("192.0.2.31"), net.ParseIP("192.0.2.32"), 32770, 443, layers.IPProtocolUDP),
			basetime.Add(31 * time.Second), true},
		{NewFlowKey(net.ParseIP("2001:db8::31"), net.ParseIP("2001:db8::32"), 32771, 80, layers.IPProtocolTCP),
			basetime.Add(32 * time.Second), true},
		{NewFlowKey(net.ParseIP("192.0.2.31"), net.ParseIP("192.0.2.32"), 32772, 443, layers.IPProtocolTCP),
			basetime.Add(33 * time.Second), true},
		{NewFlowKey(net.ParseIP("2001:db8::31"), net.ParseIP("2001:db8::32"), 32769, 443, layers.IPProtocolTCP),
			basetime.Add(35 * time.Second), false},
		{NewFlowKey(net.ParseIP("192.0.2.31"), net.ParseIP("192.0.2.32"), 32772, 443, layers.IPProtocolTCP),
			basetime.Add(36 * time.Second), false},
		{NewFlowKey(net.ParseIP("2001:db8::31"), net.ParseIP("2001:db8::32"), 32771, 80, layers.IPProtocolTCP),
			basetime.Add(37 * time.Second), false},
		{NewFlowKey(net.ParseIP("192.0.2.31"), net.ParseIP("192.0.2.32"), 32770, 443, layers.IPProtocolUDP),
			basetime.Add(39 * time.Second), false},
	}

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
