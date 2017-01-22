package mokumokuren

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const FwdOctCount = 0x0001
const FwdPktCount = 0x0002
const RevOctCount = 0x0003
const RevPktCount = 0x0004

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
		fe.Counters[RevOctCount] += int(ip.Length)
	}
	return true
}

func ip6OctetCount(fe *FlowEntry, pe PacketEvent, layer gopacket.Layer) bool {
	ip := layer.(*layers.IPv6)
	if pe.Reverse {
		fe.Counters[RevOctCount] += int(ip.Length)
	} else {
		fe.Counters[RevOctCount] += int(ip.Length)
	}
	return true
}

func ChainBasicCounters(ft *FlowTable) {
	ft.AddLayerFunction(packetCount, layers.LayerTypeIPv4)
	ft.AddLayerFunction(packetCount, layers.LayerTypeIPv6)
	ft.AddLayerFunction(ip4OctetCount, layers.LayerTypeIPv4)
	ft.AddLayerFunction(ip6OctetCount, layers.LayerTypeIPv6)
}

const TCPFinStateData = 0x0005

type TCPFinState struct {
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
		fe.Finish()
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
	}

	return true
}

func ChainTCPFinishing(ft *FlowTable) {
	ft.AddInitialFunction(tcpFinStateInit)
	ft.AddLayerFunction(tcpFinStateTrack, layers.LayerTypeTCP)
}
