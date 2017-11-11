package mokumokuren_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	moku "github.com/britram/mokumokuren"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type ExpectedRTTMetrics struct {
	Handshake time.Duration
	Minimum   time.Duration
	Mean      time.Duration
	Count     uint
}

type ExpectedFlowRTTs map[moku.FlowKey]ExpectedRTTMetrics

var RTTEmitterLog *os.File

func init() {
	if DumpExpectedFlows {
		var err error
		RTTEmitterLog, err = os.Create("testdata/rtt_test.log")
		if err != nil {
			panic(err)
		}
	}
}

func rttVerificationEmitter(t *testing.T, filename string, e ExpectedFlowRTTs) moku.FlowChainFn {
	return func(fe *moku.FlowEntry) bool {

		rttdata := fe.Data[moku.RTTDataIndex].(*moku.RTTData)

		if DumpExpectedFlows {
			fmt.Fprintf(RTTEmitterLog, "// in file %s\n", filename)
			fmt.Fprintf(RTTEmitterLog, "{\"%s\",\"%s\",%d,%d,%d}: ExpectedRTTMetrics{%d,%d,%d,%d}\n",
				fe.Key.Sip, fe.Key.Dip, fe.Key.Sp, fe.Key.Dp, fe.Key.P,
				rttdata.HandshakeRTT, rttdata.MinimumRTT, rttdata.MeanRTT, rttdata.RTTSampleCount)
		}

		metrics, ok := e[fe.Key]
		if ok {
			if metrics.Handshake != rttdata.HandshakeRTT {
				t.Logf("flow %s expected hsrtt %d got %d", fe.Key, metrics.Handshake, rttdata.HandshakeRTT)
				t.Fail()
			}
			if metrics.Minimum != rttdata.MinimumRTT {
				t.Logf("flow %s expected minrtt %d got %d", fe.Key, metrics.Minimum, rttdata.MinimumRTT)
				t.Fail()
			}
			if metrics.Mean != rttdata.MeanRTT {
				t.Logf("flow %s expected meanrtt %d got %d", fe.Key, metrics.Mean, rttdata.MeanRTT)
				t.Fail()
			}
			if metrics.Count != rttdata.RTTSampleCount {
				t.Logf("flow %s expected samplecount %d got %d", fe.Key, metrics.Count, rttdata.RTTSampleCount)
				t.Fail()
			}
		}
		return true
	}
}
func TestRTTMeasurement(t *testing.T) {

	moku.QUICPort = 4433

	specs := []struct {
		filename    string
		expectation ExpectedFlowRTTs
	}{
		{"testdata/magpie_v6.pcap",
			ExpectedFlowRTTs{
				{"2001:67c:370:128:10b8:6449:2dbf:4fc", "2a03:b0c0:3:d0::27a1:1", 61040, 443, 6}: ExpectedRTTMetrics{183653000, 188679000, 378764714, 7},
			},
		},
		{"testdata/quicly.pcap",
			ExpectedFlowRTTs{
				{"127.0.0.1", "127.0.0.1", 53188, 4433, 17}: ExpectedRTTMetrics{1166000, 0, 0, 0},
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
		ft.AddEmitterFunction(rttVerificationEmitter(t, spec.filename, spec.expectation))

		for p := range ps.Packets() {
			ft.HandlePacket(p)
		}

		ft.Shutdown()
	}
}
