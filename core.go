package mokumokuren

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"sync"
	"time"
)

type PacketEvent struct {
	Packet    gopacket.Packet
	Timestamp time.Time
	Reverse   bool
}

type FlowKey struct {
	l3, l4 gopacket.Flow
	proto  layers.IPProtocol
}

func NewFlowKey(sip net.IP, dip net.IP, sp uint16, dp uint16, proto layers.IPProtocol) (k FlowKey) {
	k.l3, _ = gopacket.FlowFromEndpoints(layers.NewIPEndpoint(sip), layers.NewIPEndpoint(dip))
	switch proto {
	case layers.IPProtocolTCP:
		k.l4, _ = gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(sp)), layers.NewTCPPortEndpoint(layers.TCPPort(dp)))
	case layers.IPProtocolUDP:
		k.l4, _ = gopacket.FlowFromEndpoints(layers.NewUDPPortEndpoint(layers.UDPPort(sp)), layers.NewUDPPortEndpoint(layers.UDPPort(dp)))
	}
	k.proto = proto
	return
}

func (k FlowKey) Reverse() FlowKey {
	return FlowKey{k.l3.Reverse(), k.l4.Reverse(), k.proto}
}

func ExtractFlowKey(pkt gopacket.Packet) (k FlowKey) {
	n := pkt.NetworkLayer()
	if n != nil {
		k.l3 = n.NetworkFlow()
		t := pkt.TransportLayer()
		if t != nil {
			k.l4 = t.TransportFlow()
		}
		switch n.(type) {
		case *layers.IPv4:
			k.proto = n.(*layers.IPv4).Protocol
		case *layers.IPv6:
			k.proto = n.(*layers.IPv6).NextHeader
		default:
			k.proto = 255
		}
	}
	return
}

// FIXME: consider making FlowEntry an interface
// and add a factory instead of doing runtime typing here.
// ...runtime typing is kind of pythonic...
type FlowEntry struct {
	Key FlowKey

	Counters  map[int]int
	Data      map[int]interface{}
	StartTime time.Time
	LastTime  time.Time

	packetChannel chan PacketEvent
	reapChannel   chan FlowKey
	flowDone      chan struct{}
}

// Mark this flow as finished. To be called by a layer chain function
// on the last packet of the flow, or by an idle flow reaper.

func (fe *FlowEntry) Finish() {
	fe.reapChannel <- fe.Key
}

func (fe *FlowEntry) String() string {
	// FIXME this gets fixed when moving to statically typed flow entries
	return fmt.Sprintf("%v", *fe)
}

type FlowChainFn func(*FlowEntry) bool

type PacketChainFn func(*FlowEntry, PacketEvent) bool

type LayerChainFn func(*FlowEntry, PacketEvent, gopacket.Layer) bool

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
	ft.initialChain = make([]PacketChainFn, 1)
	ft.layerChain = make([]layerChainEntry, 4)
	ft.emitterChain = make([]FlowChainFn, 1)
	ft.active = make(map[FlowKey]*FlowEntry)
	ft.reapChannel = make(chan FlowKey)
	ft.reaperDone = make(chan struct{})
	ft.tickChannel = make(chan time.Time)

	// start the flow table's emitter
	go ft.reapFinishedFlowEntries()

	// start the idle reaper
	go ft.reapIdleFlowEntries()

	return
}

func (ft *FlowTable) HandlePacket(pkt gopacket.Packet) {
	// advance the packet clock
	timestamp := pkt.Metadata().Timestamp
	ft.tickPacketClock(timestamp)

	// extract a flow key from the packet
	k := ExtractFlowKey(pkt)

	// get a flow entry for the flow key, tick the idle queue,
	// and send it the packet for further processing if not ignored.
	fe, rev := ft.flowEntry(k)
	if fe != nil {
		ft.idleq.Tick(k, timestamp)
		fe.packetChannel <- PacketEvent{pkt, timestamp, rev}
	}
}

func (ft *FlowTable) Shutdown() {

	ft.activeLock.RLock()
	keylist := make([]FlowKey, len(ft.active))
	for k := range ft.active {
		keylist = append(keylist, k)
	}
	ft.activeLock.RUnlock()

	for _, k := range keylist {
		ft.reapChannel <- k
	}

	// Shut down the reapers
	close(ft.tickChannel)
	close(ft.reapChannel)

	// and wait
	_ = <-ft.reaperDone
}

func (ft *FlowTable) AddInitialFunction(fn PacketChainFn) {
	ft.initialChain = append(ft.initialChain, fn)
}

func (ft *FlowTable) AddLayerFunction(fn LayerChainFn, layerType gopacket.LayerType) {
	ft.layerChain = append(ft.layerChain, layerChainEntry{layerType, fn})
}

func (ft *FlowTable) AddEmitterFunction(fn FlowChainFn) {
	ft.emitterChain = append(ft.emitterChain, fn)
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
	fe.Counters = make(map[int]int)
	fe.Data = make(map[int]interface{})
	fe.packetChannel = make(chan PacketEvent)
	fe.reapChannel = ft.reapChannel
	fe.flowDone = make(chan struct{})

	// Now start running the function chain for this flow entry
	// in its own goroutine
	go func() {
		initial := true

		// Run forever. FlowEntry goroutines are shut down by
		// closing the packet channel.
		for pe := range fe.packetChannel {

			if fe.LastTime.Before(pe.Timestamp) {
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
		}

		// let the reaper know we're done
		close(fe.flowDone)
	}()

	// Add the flow to the active table
	ft.activeLock.Lock()
	ft.active[key] = fe
	ft.activeLock.Unlock()

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

	lastClock := ft.packetClock
	ft.packetClock = tick

	// generate ticks for reapIdleFlowEntries
	for i, j := quantize(lastClock, BIN_QUANTUM), quantize(tick, BIN_QUANTUM); i.Before(j); i = i.Add(BIN_QUANTUM * time.Second) {
		ft.tickChannel <- i
	}

}

func (ft *FlowTable) reapIdleFlowEntries() {
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
}

func (ft *FlowTable) reapFinishedFlowEntries() {
	for k := range ft.reapChannel {
		// get the flow
		ft.activeLock.RLock()
		fe := ft.active[k]
		ft.activeLock.RUnlock()

		// remove the flow from the active table
		ft.activeLock.Lock()
		delete(ft.active, k)
		ft.activeLock.Unlock()

		// close the packet channel
		close(fe.packetChannel)

		// wait for flow's goroutine to complete
		_ = <-fe.flowDone

		// now run the emitter chain
		for _, fn := range ft.emitterChain {
			if !fn(fe) {
				break
			}
		}
	}

	// signal done
	close(ft.reaperDone)
}
