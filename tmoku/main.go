package main

import (
	"flag"
	"github.com/britram/mokumokuren"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
)

func main() {
	fileflag := flag.String("file", "-", "pcap file to read packets from")

	// parse command line
	flag.Parse()

	// set up sigterm handling
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		_ = <-interrupt
		pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
		panic("interrupted, dumping stacks")
	}()

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
	defer handle.Close()

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	// iterate over packets and stuff them in the flow table
	for pkt := range ps.Packets() {
		ft.HandlePacket(pkt)
	}

	log.Printf("******************** after packet iterator ***********************")

	// at EOF, flush the flowtable
	ft.Shutdown()
}
