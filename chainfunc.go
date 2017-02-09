package mokumokuren

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"strings"
	"time"
)

// Counter field numbers

const (
	FwdOctCount = iota
	FwdPktCount
	RevOctCount
	RevPktCount
	TCPFinStateData
	TCPRTTData
)

///////////////////////////////////////////////////////////////////////
//
// Basic counters: forward and reverse packets and (IP) octets
//
///////////////////////////////////////////////////////////////////////

func packetCount(fe *FlowEntry, pe PacketEvent, layer gopacket.Layer) bool {
	if pe.Reverse {
		fe.Counters[RevPktCount] += 1
	} else {
		fe.Counters[FwdPktCount] += 1
	}
	return true
}

func ip4OctetCount(fe *FlowEntry, pe PacketEvent, layer gopacket.Layer) bool {
	ip := layer.(*layers.IPv4)
	if pe.Reverse {
		fe.Counters[RevOctCount] += int(ip.Length)
	} else {
		fe.Counters[FwdOctCount] += int(ip.Length)
	}
	return true
}

func ip6OctetCount(fe *FlowEntry, pe PacketEvent, layer gopacket.Layer) bool {
	ip := layer.(*layers.IPv6)
	if pe.Reverse {
		fe.Counters[RevOctCount] += int(ip.Length)
	} else {
		fe.Counters[FwdOctCount] += int(ip.Length)
	}
	return true
}

func (ft *FlowTable) ChainBasicCounters() {
	ft.AddLayerFunction(packetCount, layers.LayerTypeIPv4)
	ft.AddLayerFunction(packetCount, layers.LayerTypeIPv6)
	ft.AddLayerFunction(ip4OctetCount, layers.LayerTypeIPv4)
	ft.AddLayerFunction(ip6OctetCount, layers.LayerTypeIPv6)
}

///////////////////////////////////////////////////////////////////////
//
// TCP FIN and RST state tracking
//
///////////////////////////////////////////////////////////////////////

type tcpFinState struct {
	rstseen  [2]bool
	finseen  [2]bool
	finacked [2]bool
	finseq   [2]uint32
}

func tcpFinStateInit(fe *FlowEntry, pe PacketEvent) bool {
	if pe.Packet.Layer(layers.LayerTypeTCP) != nil {
		fe.Data[TCPFinStateData] = new(tcpFinState)
	}
	return true
}

func tcpFinStateTrack(fe *FlowEntry, pe PacketEvent, layer gopacket.Layer) bool {
	state := fe.Data[TCPFinStateData].(*tcpFinState)
	tcp := layer.(*layers.TCP)
	var fwd, rev int
	if pe.Reverse {
		fwd, rev = 1, 0
	} else {
		fwd, rev = 0, 1
	}

	if tcp.RST {
		state.rstseen[fwd] = true
		fe.Finish()
		return false
	}

	if tcp.FIN {
		state.finseen[fwd] = true
		state.finseq[fwd] = tcp.Seq
	}

	if state.finseen[rev] && tcp.ACK && tcp.Ack == state.finseq[rev] {
		state.finacked[rev] = true
	}

	if state.finacked[fwd] && state.finacked[rev] {
		fe.Finish()
		return false
	}

	return true
}

// Adds functions for finishing flows on TCP FIN and RST
// to a given flow table
func (ft *FlowTable) ChainTCPFinishing() {
	ft.AddInitialFunction(tcpFinStateInit)
	ft.AddLayerFunction(tcpFinStateTrack, layers.LayerTypeTCP)
}

///////////////////////////////////////////////////////////////////////
//
// TCP loss and RTT tracking (from QoF)
//
///////////////////////////////////////////////////////////////////////f

const defaultRttSmoothingAlpha = 8

func tcpSeqCmp(a, b uint32) int {
	if a == b {
		return 0
	} else if (a-b)&0x80000000 > 0 {
		return -1
	} else {
		return 1
	}
}

func extractTSOPT(tcp *layers.TCP) (tsval, tsecr uint32, ok bool) {
	for _, opt := range tcp.Options {
		if opt.OptionType == layers.TCPOptionKindTimestamps {
			tsval = binary.BigEndian.Uint32(opt.OptionData[0:4])
			tsecr = binary.BigEndian.Uint32(opt.OptionData[4:8])
			ok = true
			return
		}
	}
	return 0, 0, false
}

type tcpRttDirection struct {
	// Next ack or TSECR expected
	wval uint32
	// Currently waiting for ack
	ackwait bool
	// Currently waiting for ecr
	ecrwait bool
	// Time at which ack/tsval was seen
	at time.Time
	// Last partial RTT observation
	obs time.Duration
}

func (dir *tcpRttDirection) waitForAck(ack uint32, at time.Time) {
	if !dir.ackwait && !dir.ecrwait {
		dir.ackwait = true
		dir.wval = ack
		dir.at = at
	}
}

func (dir *tcpRttDirection) waitForEcr(ecr uint32, at time.Time) {
	if !dir.ecrwait && !dir.ackwait {
		dir.ecrwait = true
		dir.wval = ecr
		dir.at = at
	}
}

type tcpRttEstimator struct {
	// Estimator state for the forward direction
	fwd tcpRttDirection
	// Estimator state for the reverse direction
	rev tcpRttDirection
	// Current estimate
	val time.Duration
	// Minimum estimate
	min time.Duration
	// Sample count
	n uint
	// Linear smoothing parameter
	a uint
}

func (est *tcpRttEstimator) sample() bool {
	if est.fwd.obs > 0 && est.rev.obs > 0 {
		est.n++
		if est.val == 0 {
			est.val = est.fwd.obs + est.rev.obs
			est.min = est.val
		} else {
			var a0, a1 time.Duration
			if est.n < est.a {
				a0 = time.Duration(est.n)
				a1 = time.Duration(est.n - 1)
			} else {
				a0 = time.Duration(est.a)
				a1 = time.Duration(est.a - 1)
			}

			est.val = (est.val*a1 + est.fwd.obs + est.rev.obs) / a0

			if est.min > est.val {
				est.min = est.val
			}
		}
		return true
	} else {
		return false
	}
}

func tcpRttInit(fe *FlowEntry, pe PacketEvent) bool {
	if pe.Packet.Layer(layers.LayerTypeTCP) != nil {
		est := new(tcpRttEstimator)
		est.a = defaultRttSmoothingAlpha
		fe.Data[TCPRTTData] = est
	}
	return true
}

func tcpRttTrack(fe *FlowEntry, pe PacketEvent, layer gopacket.Layer) bool {
	tcp := layer.(*layers.TCP)
	est := fe.Data[TCPRTTData].(*tcpRttEstimator)
	tsval, tsecr, tsok := extractTSOPT(tcp)

	var fdir, rdir *tcpRttDirection
	if pe.Reverse {
		rdir, fdir = &est.fwd, &est.rev
	} else {
		fdir, rdir = &est.fwd, &est.rev
	}

	// check to see if we got an ack we're waiting for
	if tcp.ACK && fdir.ackwait && tcpSeqCmp(tcp.Ack, fdir.wval) >= 0 {
		fdir.obs = pe.Timestamp.Sub(fdir.at)
		_ = est.sample()
		fdir.ackwait = false
		// check to see if we got an ecr we're waiting for
	} else if fdir.ecrwait && tsok && tcpSeqCmp(tsecr, fdir.wval) >= 0 {
		fdir.obs = pe.Timestamp.Sub(fdir.at)
		_ = est.sample()
		fdir.ecrwait = false
	}

	// try to wait for ecr; failing that, try to wait for ack
	if tsok {
		rdir.waitForEcr(tsval, pe.Timestamp)
	} else {
		rdir.waitForAck(tcp.Seq, pe.Timestamp)
	}

	// keep processing
	return true
}

// Adds functions for finishing flows on TCP FIN and RST
// to a given flow table
func (ft *FlowTable) ChainTCPRTT() {
	ft.AddInitialFunction(tcpRttInit)
	ft.AddLayerFunction(tcpRttTrack, layers.LayerTypeTCP)
}

///////////////////////////////////////////////////////////////////////
//
// Basic emitters
//
///////////////////////////////////////////////////////////////////////f

// Emitter chain function to print flow records containing
// information from the provided chains to the log

func BasicLogEmitter(fe *FlowEntry) bool {

	additional := make([]string, 0)

	// try to get rtt data
	rv := fe.Data[TCPRTTData]
	if rv != nil {
		est := rv.(tcpRttEstimator)
		additional = append(additional, fmt.Sprintf("rtt %d ms", est.val/1000))
	}

	// try to get fin state data for a flow end reason
	fv := fe.Data[TCPFinStateData]
	if fv != nil {
		fs := fv.(tcpFinState)
		if fs.finacked[0] && fs.finacked[1] {
			additional = append(additional, "FIN")
		} else if fs.finacked[0] || fs.finacked[1] {
			additional = append(additional, "half-FIN")
		} else if fs.rstseen[0] || fs.rstseen[1] {
			additional = append(additional, "RST")
		} else {
			additional = append(additional, "idle")
		}

	}

	log.Printf("%v (%d/%d -> %d/%d) %s", fe.Key,
		fe.Counters[FwdOctCount], fe.Counters[FwdPktCount],
		fe.Counters[RevOctCount], fe.Counters[RevPktCount],
		strings.Join(additional, " "))
	return true
}
