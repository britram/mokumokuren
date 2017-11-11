package mokumokuren

import (
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

	initialTCPTimestamp bool
	useTCPTimestamps    bool
	awaitTime           [2]*time.Time
	awaitVal            [2]uint32
}

///////////////////////////////////////////////////////////////////////
//
// TCP handshake tracking
//
//////////////////////////////////////////////////////////////////////

// for checking TCP handshake RTT
func rttTCPPacket(fe *FlowEntry, pe *PacketEvent, layer gopacket.Layer) bool {
	tcp := layer.(*layers.TCP)
	rttdata := fe.Data[RTTDataIndex].(*RTTData)

	// Calculate handshake RTT
	if rttdata.firstReverse == nil && pe.Reverse && tcp.SYN && tcp.ACK {
		rttdata.firstReverse = pe.Timestamp
	} else if rttdata.secondForward == nil && !pe.Reverse && !tcp.SYN {
		rttdata.secondForward = pe.Timestamp
		rttdata.HandshakeRTT = rttdata.secondForward.Sub(*fe.StartTime)
	}

	return true
}

func (ft *FlowTable) TrackRoundTripTime() {
	ft.AddLayerFunction(rttTCPPacket, layers.LayerTypeTCP)
}
