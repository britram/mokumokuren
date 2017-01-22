package mokumokuren

import (
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"log"
	"sync"
	"time"
)

type TimedPacket struct {
	Timestamp time.Time
	Packet    gopacket.Packet
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
	Counters  map[string]int
	Data      map[string]interface{}
	StartTime time.Time
	LastTime  time.Time

	packetChannel chan TimedPacket
	reapChannel   chan *FlowEntry
	flowDone      chan struct{}
}

// Mark this flow as finished. To be called by a layer chain function
// on the last packet of the flow, or by an idle flow reaper.

func (fe *FlowEntry) Finish() {
	fe.reapChannel <- fe
}

type FlowChainFn func(*FlowEntry) bool

type PacketChainFn func(*FlowEntry, gopacket.Packet) bool

type LayerChainFn func(*FlowEntry, gopacket.Layer) bool

type LayerChainEntry struct {
	LayerType gopacket.LayerType
	Fn        LayerChainFn
}

// Contains the set of currently active flows
type FlowTable struct {
	// Function chain to run on the first packet in any given flow.
	// Used to set up state for subsequent chains
	InitialChain []PacketChainFn

	// Function chain to run for each layer of each incoming packet
	LayerChain []LayerChainEntry

	// Function chain to run on concluded flows
	EmitterChain []FlowChainFn

	// The current time as of the last packet added to the flow
	PacketClock time.Time

	// Currently active flows, maps a flow key to a flow entry.
	Active     map[gopacket.Flow]*FlowEntry
	activeLock sync.RWMutex

	// Channel for flow entries to be reaped from the active queue
	reapChannel chan *FlowEntry

	// Channel for packet clock ticks
	tickChannel chan time.Time
}

func NewFlowTable() (ft *FlowTable) {
	ft = new(FlowTable)
	ft.InitialChain = make([]PacketChainFn, 1)
	ft.LayerChain = make([]LayerChainEntry, 4)
	ft.EmitterChain = make([]FlowChainFn, 1)
	ft.Active = make(map[gopacket.Flow]*FlowEntry)
	ft.reapChannel = make(chan *FlowEntry)

	// start the flow table's emitter
	go ft.reapFinishedFlowEntries()

	// start the idle reaper
	go ft.reapIdleFlowEntries()

	return
}

func (ft *FlowTable) HandlePacket(pkt gopacket.Packet, ci gopacket.CaptureInfo) {
	// advance the packet clock
	ft.tickPacketClock(ci.Timestamp)

	// extract a flow key from the packet
	flow, ok := flowKey(pkt)
	if ok {
		// get a flow entry for the flow key,
		// and send it the packet for further processing if not ignored.
		fe := ft.flowEntry(flow)
		if fe != nil {
			fe.packetChannel <- TimedPacket{ci.Timestamp, pkt}
		}
	}
}

func (ft *FlowTable) flowEntry(flow gopacket.Flow) (fe *FlowEntry) {
	// First look for a flow entry in the active table
	var ok bool
	ft.activeLock.RLock()
	fe, ok = ft.Active[flow]
	ft.activeLock.RUnlock()

	if ok {
		return
	}

	// No entry available. Create a new one.
	fe = new(FlowEntry)
	fe.Key = flow
	fe.Counters = make(map[string]int)
	fe.Data = make(map[string]interface{})
	fe.packetChannel = make(chan TimedPacket)
	fe.reapChannel = ft.reapChannel
	fe.flowDone = make(chan struct{})

	// Now start running the function chain for this flow entry
	// in its own goroutine
	go func() {
		initial := true

		// Run forever. FlowEntry goroutines are shut down by
		// closing the packet channel.
		for tpkt := range fe.packetChannel {

			if fe.LastTime.Before(tpkt.Timestamp) {
				fe.LastTime = tpkt.Timestamp
			}

			// The initial function chain is used to set up
			// state in the FlowEntry to be used by
			// functions in the layer chain.
			if initial {
				fe.StartTime = tpkt.Timestamp
				for _, fn := range ft.InitialChain {
					if !fn(fe, tpkt.Packet) {
						break
					}
				}
				initial = false
			}

			// The layer chain contains functions to be
			// called for specified layers in a
			// specified order
			for _, le := range ft.LayerChain {
				layer := tpkt.Packet.Layer(le.LayerType)
				if layer != nil {
					if !le.Fn(fe, layer) {
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
	fe, ok = ft.Active[flow]
	ft.activeLock.Unlock()

	return
}

func quantize(tick time.Time, quantum int64) time.Time {
	return time.Unix((tick.Unix()/quantum)*quantum, 0)
}

const BIN_QUANTUM = 10

func (ft *FlowTable) tickPacketClock(tick time.Time) {
	if ft.PacketClock.After(tick) {
		return
	}

	lastClock := ft.PacketClock
	ft.PacketClock = tick

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
		delete(ft.Active, fe.Key)
		ft.activeLock.Unlock()

		// close the packet channel
		close(fe.packetChannel)

		// wait for flow's goroutine to complete
		_ = <-fe.flowDone

		// now run the emitter chain
		for _, fn := range ft.EmitterChain {
			if !fn(fe) {
				break
			}
		}
	}
}
