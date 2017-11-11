package mokumokuren_test

import (
	"testing"
	"time"

	moku "github.com/britram/mokumokuren"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type ExpectedRTTMetrics struct {
	Handshake time.Duration
	Minimum   time.Duration
}

type ExpectedFlowRTTs map[moku.FlowKey]ExpectedRTTMetrics

func TestRTTMeasurement(t *testing.T) {

	specs := []struct {
		filename    string
		expectation ExpectedFlowRTTs
	}{
		{"testdata/magpie_v6.pcap",
			ExpectedFlowRTTs{
				{"2001:67c:370:128:98a9:b532:999b:b216", "2a03:b0c0:3:d0::27a1:1", 52319, 443, 6}: {0, 0},
			},
		},
	}

	for _, spec := range specs {
		handle, err := pcap.OpenOffline(spec.filename)
		if err != nil {
			t.Fatal(err.Error())
		}
		defer handle.Close()

		ps := gopacket.NewPacketSource(handle, handle.LinkType())

		ft := moku.NewFlowTable()
		ft.CountPacketsAndOctets()
		ft.TrackTCPClose()
		ft.TrackRoundTripTime()

		for p := range ps.Packets() {
			ft.HandlePacket(p)
		}

		ft.Shutdown()
	}
}
