package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"

	"github.com/britram/mokumokuren"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

    ft.ChainGoFunctions()
	// do simple counting and TCP state tracking
	//ft.ChainBasicCounters()
	//ft.ChainTCPFinishing()
	// ft.ChainTCPRTT() // this doesn't work yet

	// add an emitter that prints flows from built in chains
	//ft.AddEmitterFunction(mokumokuren.BuiltinLogEmitter)

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

	// at EOF, flush the flowtable
	ft.Shutdown()
}
