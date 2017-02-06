package mokumokuren

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
)

const FwdOctCount = 1
const FwdPktCount = 2
const RevOctCount = 3
const RevPktCount = 4

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

const TCPFinStateData = 5

type TCPFinState struct {
	rstseen  [2]bool
	finseen  [2]bool
	finacked [2]bool
	finseq   [2]uint32
}

func tcpFinStateInit(fe *FlowEntry, pe PacketEvent) bool {
	fe.Data[TCPFinStateData] = TCPFinState{}
	return true
}

func tcpFinStateTrack(fe *FlowEntry, pe PacketEvent, layer gopacket.Layer) bool {
	state := fe.Data[TCPFinStateData].(TCPFinState)
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

func (ft *FlowTable) ChainTCPFinishing() {
	ft.AddInitialFunction(tcpFinStateInit)
	ft.AddLayerFunction(tcpFinStateTrack, layers.LayerTypeTCP)
}

func BasicLogEmitter(fe *FlowEntry) bool {
	var flowstate string
	if fe.Data[TCPFinStateData].(TCPFinState).finacked[0] && fe.Data[TCPFinStateData].(TCPFinState).finacked[1] {
		flowstate = "FIN"
	} else if fe.Data[TCPFinStateData].(TCPFinState).finacked[0] || fe.Data[TCPFinStateData].(TCPFinState).finacked[1] {
		flowstate = "half-FIN"
	} else if fe.Data[TCPFinStateData].(TCPFinState).rstseen[0] || fe.Data[TCPFinStateData].(TCPFinState).rstseen[1] {
		flowstate = "RST"
	} else {
		flowstate = "idle"
	}

	log.Printf("%v (%d/%d -> %d/%d) %s", fe.Key,
		fe.Counters[FwdOctCount], fe.Counters[FwdPktCount],
		fe.Counters[RevOctCount], fe.Counters[RevPktCount],
		flowstate)
	return true
}
