package mokumokuren_test

import (
	"fmt"
	"os"
	"testing"

	moku "github.com/britram/mokumokuren"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type ExpectedCounters struct {
	FwdPktCount uint64
	RevPktCount uint64
	FwdOctCount uint64
	RevOctCount uint64
}

type ExpectedFlows map[moku.FlowKey]ExpectedCounters

const DumpExpectedFlows = true

var CoreEmitterLog *os.File

func init() {
	if DumpExpectedFlows {
		var err error
		CoreEmitterLog, err = os.Create("testdata/core_test.log")
		if err != nil {
			panic(err)
		}
	}
}

func coreVerificationEmitter(t *testing.T, filename string, e ExpectedFlows) moku.FlowChainFn {
	return func(fe *moku.FlowEntry) bool {

		if DumpExpectedFlows {
			fmt.Fprintf(CoreEmitterLog, "// in file %s\n", filename)
			fmt.Fprintf(CoreEmitterLog, "{\"%s\",\"%s\",%d,%d,%d}: ExpectedCounters{%d,%d,%d,%d}\n",
				fe.Key.Sip, fe.Key.Dip, fe.Key.Sp, fe.Key.Dp, fe.Key.P,
				fe.FwdPktCount, fe.RevPktCount, fe.FwdOctCount, fe.RevOctCount)
		}

		counters, ok := e[fe.Key]
		if ok {
			if counters.FwdPktCount != fe.FwdPktCount {
				t.Logf("flow %s expected fpkt %d got %d", fe.Key, counters.FwdPktCount, fe.FwdPktCount)
				t.Fail()
			}
			if counters.FwdOctCount != fe.FwdOctCount {
				t.Logf("flow %s expected foct %d got %d", fe.Key, counters.FwdOctCount, fe.FwdOctCount)
				t.Fail()
			}
			if counters.RevPktCount != fe.RevPktCount {
				t.Logf("flow %s expected rpkt %d got %d", fe.Key, counters.RevPktCount, fe.RevPktCount)
				t.Fail()
			}
			if counters.RevOctCount != fe.RevOctCount {
				t.Logf("flow %s expected roct %d got %d", fe.Key, counters.RevOctCount, fe.RevOctCount)
				t.Fail()
			}
		}
		return true
	}
}

// yeah some tests would be good.
func TestPcapRead(t *testing.T) {

	specs := []struct {
		filename    string
		expectation ExpectedFlows
	}{
		{"testdata/magpie_v6.pcap",
			ExpectedFlows{
				{"2001:67c:370:128:10b8:6449:2dbf:4fc", "2a03:b0c0:3:d0::27a1:1", 61040, 443, 6}: ExpectedCounters{32, 36, 1492, 44014},
			},
		},
		{"testdata/github.pcap",
			ExpectedFlows{
				{"31.133.128.140", "192.30.255.113", 56248, 443, 6}: ExpectedCounters{27, 28, 4868, 28241},
			},
		},
		{"testdata/quadeight.pcap",
			ExpectedFlows{
				{"31.133.128.140", "8.8.8.8", 63975, 53, 17}: ExpectedCounters{1, 1, 62, 78},
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
		ft.AddEmitterFunction(coreVerificationEmitter(t, spec.filename, spec.expectation))

		for p := range ps.Packets() {
			ft.HandlePacket(p)
		}

		ft.Shutdown()
	}
}
