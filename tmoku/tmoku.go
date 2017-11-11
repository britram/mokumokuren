package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"

	moku "github.com/britram/mokumokuren"
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
	ft := moku.NewFlowTable()

	// do simple counting and TCP state tracking
	ft.CountPacketsAndOctets()
	ft.TrackTCPClose()

	// do RTTs
	ft.TrackRoundTripTime()

	// add an emitter that prints flows including rtts
	ft.AddEmitterFunction(func(fe *moku.FlowEntry) bool {
		rttdata := fe.Data[moku.RTTDataIndex].(*moku.RTTData)
		log.Printf("%s RTT %.3f/%.3f/%.3f", fe,
			float64(rttdata.HandshakeRTT)/float64(1000000),
			float64(rttdata.MinimumRTT)/float64(1000000),
			float64(rttdata.MeanRTT)/float64(1000000))

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

	// at EOF, flush the flowtable
	ft.Shutdown()
}
