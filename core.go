// Mokumokuren is an extensible flow meter. It is built around a flow table,
// which takes packets (from GoPacket), classifies them into bidirectional
// flows by 5-tuple (IP addresses, transport-layer ports, and protocol), and
// runs them through a set of functions bound to the flow table at runtime.
// These functions take information from the packets and use it to generate
// flow-level information.
//
// To use this package, create a flow table, attach measurement functions to
// it, feeding it packets until you're out of packets, then shut it down:
//
//      ps := ...some GoPacket packet source...
//
//		ft := mokumokuren.NewFlowTable()
//		ft.CountPacketsAndOctets()  // count octets and packets per flow
//		ft.TrackTCPClose()          // track TCP FIN/RST flags
//
//		for p := range ps.Packets() {
//			ft.HandlePacket(p)
//		}
//		ft.Shutdown()

package mokumokuren

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const channelQueueLength = 64

// PacketEvent represents the arrival of a packet at a given time.
type PacketEvent struct {
	// the packet that arrived
	Packet gopacket.Packet
	// time at which the packet arrived
	Timestamp *time.Time
	// set if the packet matched a reverse flow key
	Reverse bool
}

type FlowKey struct {
	Sip string // FIXME this is a stupid hack but net.IP isn't comparable
	Dip string // FIXME this is a stupid hack but net.IP isn't comparable
	Sp  uint16
	Dp  uint16
	P   uint8
}

// Return a string representation of this FlowKey suitable for printing
func (key FlowKey) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d %d", key.Sip, key.Sp, key.Dip, key.Dp, key.P)
}

// Return the reverse of this FlowKey,
// with source and destination address and port flipped.
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{k.Dip, k.Sip, k.Dp, k.Sp, k.P}
}

// Extract a flow key from a packet
func ExtractFlowKey(pkt gopacket.Packet) (k FlowKey) {
	nl := pkt.NetworkLayer()
	if nl == nil {
		// ain't nobody got time for non-IP packets. empty flow key.
		return
	}

	switch nl.(type) {
	case *layers.IPv4:
		k.Sip = nl.(*layers.IPv4).SrcIP.String() // FIXME eww eww hack
		k.Dip = nl.(*layers.IPv4).DstIP.String() // FIXME eww eww hack
		k.P = uint8(nl.(*layers.IPv4).Protocol)
	case *layers.IPv6:
		k.Sip = nl.(*layers.IPv6).SrcIP.String() // FIXME eww eww hack
		k.Dip = nl.(*layers.IPv6).DstIP.String() // FIXME eww eww hack
		k.P = uint8(nl.(*layers.IPv6).NextHeader)
	default:
		// um i got nothing, empty flow key.
		return
	}

	tl := pkt.TransportLayer()
	if tl == nil {
		// no transport layer, so try to decode ICMP
		if micmpl := pkt.Layer(layers.LayerTypeICMPv4); micmpl != nil {
			icmpl := micmpl.(*layers.ICMPv4)
			icmptype := icmpl.TypeCode.Type()
			if icmptype == layers.ICMPv4TypeDestinationUnreachable ||
				icmptype == layers.ICMPv4TypeTimeExceeded ||
				icmptype == layers.ICMPv4TypeParameterProblem {
				// Account ICMPv4 messages from routers to the
				// reverse flow they belong to
				sk := ExtractFlowKey(gopacket.NewPacket(icmpl.LayerPayload(),
					layers.LayerTypeIPv4,
					gopacket.Default))
				k.Sip = sk.Dip
				k.Sp = sk.Dp
				k.P = sk.P
			} else {
				k.Sp = uint16(icmpl.TypeCode.Type())
				k.Dp = uint16(icmpl.TypeCode.Code())
			}
		} else if micmpl := pkt.Layer(layers.LayerTypeICMPv6); micmpl != nil {
			icmpl := micmpl.(*layers.ICMPv6)
			icmptype := icmpl.TypeCode.Type()
			if icmptype == layers.ICMPv6TypeDestinationUnreachable ||
				icmptype == layers.ICMPv6TypeTimeExceeded ||
				icmptype == layers.ICMPv6TypePacketTooBig ||
				icmptype == layers.ICMPv6TypeParameterProblem {
				// Account ICMPv6 messages from routers to the
				// reverse flow they belong to
				sk := ExtractFlowKey(gopacket.NewPacket(icmpl.LayerPayload(),
					layers.LayerTypeIPv6,
					gopacket.Default))
				k.Sip = sk.Dip
				k.Sp = sk.Dp
				k.P = sk.P
			} else {
				k.Sp = uint16(icmpl.TypeCode.Type())
				k.Dp = uint16(icmpl.TypeCode.Code())
			}
		} else {
			// no icmp, no transport, no ports for you
			return
		}
	}

	switch tl.(type) {
	case *layers.TCP:
		k.Sp = uint16(tl.(*layers.TCP).SrcPort)
		k.Dp = uint16(tl.(*layers.TCP).DstPort)
	case *layers.UDP:
		k.Sp = uint16(tl.(*layers.UDP).SrcPort)
		k.Dp = uint16(tl.(*layers.UDP).DstPort)
	case *layers.UDPLite:
		k.Sp = uint16(tl.(*layers.UDPLite).SrcPort)
		k.Dp = uint16(tl.(*layers.UDPLite).DstPort)
	case *layers.SCTP:
		k.Sp = uint16(tl.(*layers.SCTP).SrcPort)
		k.Dp = uint16(tl.(*layers.SCTP).DstPort)
	default:
		// no transport layer we know about, so no ports.
		return
	}

	// key set
	return
}

var dataCount int

func RegisterDataIndex() int {
	dataCount++
	return dataCount - 1
}

// FIXME: make FlowEntry an interface? see #1.
type FlowEntry struct {
	// Flow key
	Key FlowKey

	// Timestamp of first packet in the flow
	StartTime *time.Time

	// Timestamp of last packet in the flow
	LastTime *time.Time

	// Count of packets observed in the forward direction
	FwdPktCount uint64

	// Count of packets observed in the reverse direction
	RevPktCount uint64

	// Count of octets observed in the forward direction
	FwdOctCount uint64

	// Count of octets observed in the reverse direction
	RevOctCount uint64

	// Arbitrary data for non-core chain functions
	Data []interface{}

	rstseen  [2]bool
	finseen  [2]bool
	finacked [2]bool
	finseq   [2]uint32

	packetChannel chan *PacketEvent
	reapChannel   chan FlowKey
	flowFinishing chan struct{}
	flowDone      chan struct{}
}

// Mark this flow as finished. To be called by a layer chain function
// on the last packet of the flow, or by an idle flow reaper.
func (fe *FlowEntry) Finish() {
	fe.reapChannel <- fe.Key
}

// Return a string representation of this flow entry
func (fe *FlowEntry) String() string {
	return fmt.Sprintf("[%s - %s] %s (%d/%d) -> (%d/%d)",
		fe.StartTime.Format(time.RFC3339),
		fe.LastTime.Format(time.RFC3339),
		fe.Key, fe.FwdPktCount, fe.FwdOctCount, fe.RevPktCount, fe.RevOctCount)
}

type FlowChainFn func(*FlowEntry) bool

type PacketChainFn func(*FlowEntry, *PacketEvent) bool

type LayerChainFn func(*FlowEntry, *PacketEvent, gopacket.Layer) bool

type layerChainEntry struct {
	LayerType gopacket.LayerType
	Fn        LayerChainFn
}

const IDLE_TIMEOUT = 30

// Contains the set of currently active flows
type FlowTable struct {
	// Function chain to run on the first packet in any given flow.
	// Used to set up state for subsequent chains
	initialChain []PacketChainFn

	// Function chain to run for each layer of each incoming packet
	layerChain []layerChainEntry

	// Function chain to run on concluded flows
	emitterChain []FlowChainFn

	// The current time as of the last packet added to the flow
	packetClock time.Time

	// Currently active flows, maps a flow key to a flow entry.
	active map[FlowKey]*FlowEntry

	// Idle queue
	idleq IdleQueue

	// Lock guarding access to the active table
	activeLock sync.RWMutex

	// Channel for flow entries to be reaped from the active queue
	reapChannel chan FlowKey
	reaperDone  chan struct{}

	// Channel for packet clock ticks
	tickChannel chan time.Time
}

func NewFlowTable() (ft *FlowTable) {
	ft = new(FlowTable)
	ft.initialChain = make([]PacketChainFn, 0)
	ft.layerChain = make([]layerChainEntry, 0)
	ft.emitterChain = make([]FlowChainFn, 0)
	ft.active = make(map[FlowKey]*FlowEntry)
	ft.reapChannel = make(chan FlowKey, channelQueueLength)
	ft.reaperDone = make(chan struct{})
	ft.tickChannel = make(chan time.Time)

	// start the flow table's emitter
	go ft.reapFinishedFlowEntries()

	// start the idle reaper
	go ft.reapIdleFlowEntries()

	return
}

func (ft *FlowTable) HandlePacket(pkt gopacket.Packet) {
	var emptyFlowKey FlowKey

	// advance the packet clock
	timestamp := pkt.Metadata().Timestamp
	ft.tickPacketClock(timestamp)

	// extract a flow key from the packet
	k := ExtractFlowKey(pkt)

	// drop packets with the zero key
	if k == emptyFlowKey {
		return
	}

	// get a flow entry for the flow key, tick the idle queue,
	// and send it the packet for further processing if not ignored.
	fe, rev := ft.flowEntry(k)
	if fe != nil {
		ft.idleq.Tick(k, timestamp)
		fe.packetChannel <- &PacketEvent{pkt, &timestamp, rev}
	}
}

func (ft *FlowTable) Shutdown() {

	//log.Printf("in shutdown")

	ft.activeLock.RLock()
	keylist := make([]FlowKey, len(ft.active))
	i := 0
	for k := range ft.active {
		keylist[i] = k
		i++
	}
	ft.activeLock.RUnlock()

	for _, k := range keylist {
		ft.reapChannel <- k
		//log.Printf("reaped %v on shutdown", k)
	}

	// Shut down the reapers
	close(ft.tickChannel)
	close(ft.reapChannel) // FIXME close race here

	// and wait
	_ = <-ft.reaperDone
}

func (ft *FlowTable) AddInitialFunction(fn PacketChainFn) {
	ft.initialChain = append(ft.initialChain, fn)
	//log.Printf("initialChain now %v", ft.initialChain)
}

func (ft *FlowTable) AddLayerFunction(fn LayerChainFn, layerType gopacket.LayerType) {
	ft.layerChain = append(ft.layerChain, layerChainEntry{layerType, fn})
	//log.Printf("layerChain now %v", ft.layerChain)
}

func (ft *FlowTable) AddEmitterFunction(fn FlowChainFn) {
	ft.emitterChain = append(ft.emitterChain, fn)
	//log.Printf("emitterChain now %v", ft.emitterChain)
}

func (ft *FlowTable) flowEntry(key FlowKey) (fe *FlowEntry, rev bool) {
	// First look for a flow entry in the active table
	ft.activeLock.RLock()
	fe = ft.active[key]
	ft.activeLock.RUnlock()

	if fe != nil {
		return fe, false
	}

	// Now look for a reverse flow entry
	ft.activeLock.RLock()
	fe = ft.active[key.Reverse()]
	ft.activeLock.RUnlock()

	if fe != nil {
		return fe, true
	}

	// No entry available. Create a new one.
	fe = new(FlowEntry)
	fe.Key = key
	fe.Data = make([]interface{}, dataCount)
	fe.packetChannel = make(chan *PacketEvent)
	fe.reapChannel = ft.reapChannel
	fe.flowFinishing = make(chan struct{})
	fe.flowDone = make(chan struct{})

	// Now start running the function chain for this flow entry
	// in its own goroutine
	go func() {
		initial := true

		// Run until we get a finishing signal.
		running := true
		for running {
			select {
			case pe := <-fe.packetChannel:
				if fe.LastTime == nil || fe.LastTime.Before(*pe.Timestamp) {
					fe.LastTime = pe.Timestamp
				}

				// The initial function chain is used to set up
				// state in the FlowEntry to be used by
				// functions in the layer chain.
				if initial {
					fe.StartTime = pe.Timestamp
					for _, fn := range ft.initialChain {
						if !fn(fe, pe) {
							break
						}
					}
					initial = false
				}

				// The layer chain contains functions to be
				// called for specified layers in a
				// specified order
				for _, le := range ft.layerChain {
					layer := pe.Packet.Layer(le.LayerType)
					if layer != nil {
						if !le.Fn(fe, pe, layer) {
							break
						}
					}
				}
			case <-fe.flowFinishing:
				running = false
			}
		}

		//log.Printf("flowroutine for key %v exiting", fe.Key)

		// let the reaper know we're done
		close(fe.flowDone)
	}()

	// Add the flow to the active table
	ft.activeLock.Lock()
	ft.active[key] = fe
	ft.activeLock.Unlock()
	//log.Printf("added new flow entry for key %s", fe.Key.String())

	return fe, false
}

func quantize(tick time.Time, quantum int64) time.Time {
	return time.Unix((tick.Unix()/quantum)*quantum, 0)
}

const BIN_QUANTUM = 10

func (ft *FlowTable) tickPacketClock(tick time.Time) {
	if ft.packetClock.After(tick) {
		return
	}

	var lastClock time.Time
	if ft.packetClock.After(time.Time{}) {
		lastClock = ft.packetClock
	} else {
		lastClock = tick
		log.Printf("initializing packet clock %v", tick)
	}

	ft.packetClock = tick

	// generate ticks for reapIdleFlowEntries
	for i, j := quantize(lastClock, BIN_QUANTUM), quantize(tick, BIN_QUANTUM); i.Before(j); i = i.Add(BIN_QUANTUM * time.Second) {
		log.Printf("ticking to %v", i)
		ft.tickChannel <- i
	}

}

func (ft *FlowTable) reapIdleFlowEntries() {
	log.Println("idle reaper up")

	for tick := range ft.tickChannel {
		endtime := tick.Add(IDLE_TIMEOUT * time.Second)
		for {
			k, ok := ft.idleq.NextIdleBefore(endtime)
			if ok {
				ft.reapChannel <- k
			} else {
				break
			}
		}
	}
	log.Println("idle reaper down")
}

func (ft *FlowTable) reapFinishedFlowEntries() {
	log.Println("finished reaper up")

	for k := range ft.reapChannel {
		// get the flow
		ft.activeLock.RLock()
		fe := ft.active[k]
		ft.activeLock.RUnlock()

		if fe == nil {
			log.Printf("**** duplicate reap of %v ****", k) // FIXME this is an error, make it not happen.
			continue
		}

		// remove the flow from the active table
		ft.activeLock.Lock()
		delete(ft.active, k)
		ft.activeLock.Unlock()

		// signal flow's goroutine to complete
		fe.flowFinishing <- struct{}{}
		//log.Printf("reaper waiting %v to finish", k)

		// and wait for it to do so
		_ = <-fe.flowDone

		//log.Printf("reaper emitting %v", k)

		// now run the emitter chain
		for _, fn := range ft.emitterChain {
			if !fn(fe) {
				break
			}
		}
	}

	// signal done
	close(ft.reaperDone)

	log.Println("finished reaper down")
}

///////////////////////////////////////////////////////////////////////
//
// Basic counters: forward and reverse packets and (IP) octets
//
///////////////////////////////////////////////////////////////////////

func packetCount(fe *FlowEntry, pe *PacketEvent, layer gopacket.Layer) bool {
	if pe.Reverse {
		fe.RevPktCount += 1
	} else {
		fe.FwdPktCount += 1
	}
	return true
}

func ip4OctetCount(fe *FlowEntry, pe *PacketEvent, layer gopacket.Layer) bool {
	ip := layer.(*layers.IPv4)
	if pe.Reverse {
		fe.RevOctCount += uint64(ip.Length)
	} else {
		fe.FwdOctCount += uint64(ip.Length)
	}
	return true
}

func ip6OctetCount(fe *FlowEntry, pe *PacketEvent, layer gopacket.Layer) bool {
	ip := layer.(*layers.IPv6)
	if pe.Reverse {
		fe.RevOctCount += uint64(ip.Length)
	} else {
		fe.FwdOctCount += uint64(ip.Length)
	}
	return true
}

func (ft *FlowTable) CountPacketsAndOctets() {
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

func wrapCompare(a, b uint32) int {
	if a == b {
		return 0
	} else if ((a - b) & 0x80000000) > 0 {
		return -1
	} else {
		return 1
	}
}

func tcpFinStateTrack(fe *FlowEntry, pe *PacketEvent, layer gopacket.Layer) bool {
	tcp := layer.(*layers.TCP)
	var fwd, rev int
	if pe.Reverse {
		fwd, rev = 1, 0
	} else {
		fwd, rev = 0, 1
	}

	if tcp.RST {
		fe.rstseen[fwd] = true
		fe.Finish()
		return false
	}

	if tcp.FIN {
		fe.finseen[fwd] = true
		fe.finseq[fwd] = tcp.Seq
	}

	if fe.finseen[rev] && tcp.ACK && wrapCompare(tcp.Ack, fe.finseq[rev]) >= 0 {
		fe.finacked[rev] = true
	}

	if fe.finacked[fwd] && fe.finacked[rev] {
		fe.Finish()
		return false
	}

	return true
}

// Adds functions for finishing flows on TCP FIN and RST
// to a given flow table
func (ft *FlowTable) TrackTCPClose() {
	ft.AddLayerFunction(tcpFinStateTrack, layers.LayerTypeTCP)
}
