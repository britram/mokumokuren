package mokumokuren

import (
	"encoding/binary"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var RTTDataIndex int

func init() {
	RTTDataIndex = RegisterDataIndex()
}

type RTTData struct {
	// Measured handshake RTT
	HandshakeRTT time.Duration

	firstReverse  *time.Time
	secondForward *time.Time

	// Minimum running RTT sample
	MinimumRTT time.Duration
	// Mean running RTT sample
	MeanRTT time.Duration
	// Number of RTT samples
	RTTSampleCount uint

	tcpTimestampSeen   [2]bool
	UsingTCPTimestamps bool

	component [2]time.Duration
	awaitTime [2]*time.Time
	awaitVal  [2]uint32
}

func extractTimestamp(tcp *layers.TCP) (uint32, uint32, bool) {
	for _, opt := range tcp.Options {
		if opt.OptionType == layers.TCPOptionKindTimestamps && len(opt.OptionData) >= 10 {
			tsval := binary.BigEndian.Uint32(opt.OptionData[2:6])
			tsecr := binary.BigEndian.Uint32(opt.OptionData[6:10])
			return tsval, tsecr, true
		}
	}
	return 0, 0, false
}

///////////////////////////////////////////////////////////////////////
//
// TCP handshake tracking
//
//////////////////////////////////////////////////////////////////////

func rttInit(fe *FlowEntry, pe *PacketEvent) bool {
	fe.Data[RTTDataIndex] = new(RTTData)
	return true
}

func wrapCompare(a, b uint32) int {
	if a == b {
		return 0
	} else if ((a - b) & 0x80000000) > 0 {
		return -1
	} else {
		return 1
	}
}

func sampleRTT(d *RTTData) {
	sample := d.component[0] + d.component[1]
	if d.RTTSampleCount == 0 {
		d.MinimumRTT = sample
		d.MeanRTT = sample
	} else {
		if sample < d.MinimumRTT {
			d.MinimumRTT = sample
		}
		d.MeanRTT = ((d.MeanRTT * time.Duration(d.RTTSampleCount)) + sample) / time.Duration(d.RTTSampleCount+1)

	}
	d.RTTSampleCount += 1
}

// for checking TCP handshake RTT
func rttTCPPacket(fe *FlowEntry, pe *PacketEvent, layer gopacket.Layer) bool {
	tcp := layer.(*layers.TCP)
	d := fe.Data[RTTDataIndex].(*RTTData)

	// Calculate handshake RTT
	if d.firstReverse == nil && pe.Reverse && tcp.SYN && tcp.ACK {
		d.firstReverse = pe.Timestamp
	} else if d.secondForward == nil && !pe.Reverse && !tcp.SYN {
		d.secondForward = pe.Timestamp
		d.HandshakeRTT = d.secondForward.Sub(*fe.StartTime)
	}

	dir := 0
	rdir := 1
	if pe.Reverse {
		dir = 1
		rdir = 0
	}

	// try to get a timestamp
	tsval, tsecr, tsok := extractTimestamp(tcp)

	// check to see if we'd like to switch to timestamps
	if tsok {
		d.tcpTimestampSeen[dir] = true

		if d.tcpTimestampSeen[0] && d.tcpTimestampSeen[1] && !d.UsingTCPTimestamps {
			d.UsingTCPTimestamps = true
			d.awaitTime[0] = nil
			d.awaitTime[1] = nil
			d.awaitVal[0] = 0
			d.awaitVal[1] = 0
		}
	}

	// check to see if we're waiting for a value that we have
	if d.awaitTime[dir] != nil {
		if (d.UsingTCPTimestamps && wrapCompare(tsecr, d.awaitVal[dir]) > 0) ||
			(!d.UsingTCPTimestamps && wrapCompare(tcp.Ack, d.awaitVal[dir]) > 0) {
			d.component[dir] = pe.Timestamp.Sub(*d.awaitTime[dir])
			d.awaitTime[dir] = nil
			sampleRTT(d)
		}
	}

	// check to see if we need to grab a new value to wait for
	if d.awaitTime[rdir] == nil {
		d.awaitTime[rdir] = pe.Timestamp
		if d.UsingTCPTimestamps {
			d.awaitVal[rdir] = tsval
		} else {
			d.awaitVal[rdir] = tcp.Seq
		}
	}

	return true
}

func (ft *FlowTable) TrackRoundTripTime() {
	ft.AddInitialFunction(rttInit)
	ft.AddLayerFunction(rttTCPPacket, layers.LayerTypeTCP)
}
