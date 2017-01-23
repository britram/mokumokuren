package mokumokuren

import (
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"log"
	"sync"
	"time"
)

type PacketEvent struct {
	Packet    gopacket.Packet
	Timestamp time.Time
	Reverse   bool
}

func flowKey(pkt gopacket.Packet) (flow gopacket.Flow, ok bool) {
	t := pkt.TransportLayer()
	if t != nil {
		return t.TransportFlow(), true
	}
	n := pkt.NetworkLayer()
	if n != nil {
		return n.NetworkFlow(), true
	}

	// FIXME add ICMP parsing
	return gopacket.Flow{}, false
}

type FlowEntry struct {
	Key       gopacket.Flow
	Counters  map[int]int
	Data      map[int]interface{}
	StartTime time.Time
	LastTime  time.Time

	packetChannel chan PacketEvent
	reapChannel   chan *FlowEntry
	flowDone      chan struct{}
}

// Mark this flow as finished. To be called by a layer chain function
// on the last packet of the flow, or by an idle flow reaper.

func (fe *FlowEntry) Finish() {
	fe.reapChannel <- fe
}

type FlowChainFn func(*FlowEntry) bool

type PacketChainFn func(*FlowEntry, PacketEvent) bool

type LayerChainFn func(*FlowEntry, PacketEvent, gopacket.Layer) bool

type layerChainEntry struct {
	LayerType gopacket.LayerType
	Fn        LayerChainFn
}

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
	active map[gopacket.Flow]*FlowEntry

	// Lock guarding access to the active table
	activeLock sync.RWMutex

	// Channel for flow entries to be reaped from the active queue
	reapChannel chan *FlowEntry

	// Channel for packet clock ticks
	tickChannel chan time.Time
}

func NewFlowTable() (ft *FlowTable) {
	ft = new(FlowTable)
	ft.initialChain = make([]PacketChainFn, 1)
	ft.layerChain = make([]layerChainEntry, 4)
	ft.emitterChain = make([]FlowChainFn, 1)
	ft.active = make(map[gopacket.Flow]*FlowEntry)
	ft.reapChannel = make(chan *FlowEntry)

	// start the flow table's emitter
	go ft.reapFinishedFlowEntries()

	// start the idle reaper
	go ft.reapIdleFlowEntries()

	return
}

func (ft *FlowTable) HandlePacket(pkt gopacket.Packet) {
	// advance the packet clock
	timestamp := pkt.Metadata().Timestamp
	ft.tickpacketClock(timestamp)

	// extract a flow key from the packet
	flow, ok := flowKey(pkt)
	if ok {
		// get a flow entry for the flow key,
		// and send it the packet for further processing if not ignored.
		fe, rev := ft.flowEntry(flow)
		if fe != nil {
			fe.packetChannel <- PacketEvent{pkt, timestamp, rev}
		}
	}
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

func (ft *FlowTable) flowEntry(flow gopacket.Flow) (fe *FlowEntry, rev bool) {
	// First look for a flow entry in the active table
	ft.activeLock.RLock()
	fe = ft.active[flow]
	ft.activeLock.RUnlock()

	if fe != nil {
		return fe, false
	}

	// Now look for a reverse flow entry
	ft.activeLock.RLock()
	fe = ft.active[flow.Reverse()]
	ft.activeLock.RUnlock()

	if fe != nil {
		return fe, true
	}

	// No entry available. Create a new one.
	fe = new(FlowEntry)
	fe.Key = flow
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
	ft.active[flow] = fe
	ft.activeLock.Unlock()

	return fe, false
}

func quantize(tick time.Time, quantum int64) time.Time {
	return time.Unix((tick.Unix()/quantum)*quantum, 0)
}

const BIN_QUANTUM = 10

func (ft *FlowTable) tickpacketClock(tick time.Time) {
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
		log.Printf("%s", tick)
		// FIXME call fe.Finish() on idle flows
		// once we figure out the best way to do LRU
	}
}

func (ft *FlowTable) reapFinishedFlowEntries() {
	for fe := range ft.reapChannel {
		// remove the flow from the active table
		ft.activeLock.Lock()
		delete(ft.active, fe.Key)
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
}
