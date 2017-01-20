package mokumokuren

import (
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
)

type PacketFn func(Flow, gopacket.Packet) bool

type Flow struct {
	Counters      map[string]int
	packetChannel chan gopacket.Packet
}

// Contains the set of currently active flows
type Flowtable struct {
	// Flows without state (i.e. unidentifiable UDP flows) will be moved to expiring
	// after StatelessIdleTimeout milliseconds since the last packet.
	StatelessIdleTimeout int

	// Flows with state (i.e. established TCP flows) will be moved to expiring
	// after StatefulIdleTimeout milliseconds since the last packet.
	StatefulIdleTimeout int

	// Flows will be emitted (without expiring) after a maximum flow duration
	// of ActiveTimeout milliseconds
	ActiveTimeout int
    
	// The current time as of the last packet added to the flow
	PacketClock time.Time

	// Currently active flows
	Active map[gopacket.Flow]*Flow

}

func (*Flowtable) HandlePacket(gopacket.Packet pkt) {
    // associate packet with flow

    // found a flow? send to channel

    // nope. create a new flow and start its goroutine.
}
