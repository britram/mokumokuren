package main

import (
	"flag"
	"github.com/britram/mokumokuren"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
)

func main() {
	fileflag := flag.String("file", "-", "pcap file to read packets from")

	// parse command line
	flag.Parse()

	// get a flowtable
	ft := mokumokuren.NewFlowTable()

	// do simple counting and TCP state tracking
	ft.ChainBasicCounters()
	ft.ChainTCPFinishing()

	// add an emitter that just prints flows
	ft.AddEmitterFunction(func(fe *mokumokuren.FlowEntry) bool {
		log.Printf("EMIT FLOW %s", fe.String())
		return true
	})

	handle, err := pcap.OpenOffline(*fileflag)
	if err != nil {
		log.Fatal(err.Error())
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	// iterate over packets and stuff them in the flow table
	for pkt := range ps.Packets() {
		ft.HandlePacket(pkt)
	}

	// at EOF, flush the flowtable
	ft.Shutdown()
}
