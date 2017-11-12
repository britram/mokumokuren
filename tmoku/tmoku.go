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
	quicportflag := flag.Uint("quic", 0, "UDP port to use for QUIC recognition")

	// parse command line
	flag.Parse()

	// set quic port
	moku.QUICPort = uint16(*quicportflag)

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
		log.Printf("%s %s", fe, rttdata)

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
