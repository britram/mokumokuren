package mokumokuren

import (
//	"encoding/binary"
//	"log"
//	"strings"
	"time"
    "fmt"
    
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
    indexMeasurementByte = 17
)

const (
    bitsetLatencySpin = 7
)

const (
    indexLastLatencySpinFWD = 0
    indexLastLatencySpinTimeFWD = 1
    indexLastLatencySpinREV = 2
    indexLastLatencySpinTimeREV = 3
)

func setUpState(fe *FlowEntry, pe PacketEvent) bool {
    packettime := pe.Timestamp.Sub(fe.StartTime)

    //udp := pe.Packet.TransportLayer().(*layers.UDP)
    //payload :=  pe.Packet.TransportLayer().LayerPayload()

    //measurement := payload[indexMeasurementByte]

    //spin := (measurement & (0x01 << bitsetLatencySpin)) >> bitsetLatencySpin

    fe.Data[indexLastLatencySpinFWD] = -1
    fe.Data[indexLastLatencySpinTimeFWD] = packettime
        fe.Data[indexLastLatencySpinREV] = -1
    fe.Data[indexLastLatencySpinTimeREV] = packettime

    fmt.Printf("New Flow: Time: %.3fs\n",
               packettime.Seconds())

    return true
}

func printMeasurementByte(fe *FlowEntry, pe PacketEvent, layer gopacket.Layer) bool {

    packettime := pe.Timestamp.Sub(fe.StartTime)

    udp := layer.(*layers.UDP)
    payload := layer.LayerPayload()
    measurement := payload[indexMeasurementByte]
    spin := (measurement & (0x01 << bitsetLatencySpin)) >> bitsetLatencySpin

    var indexLastLatencySpin, indexLastLatencySpinTime int

    if udp.DstPort == 4433 {
        indexLastLatencySpin = indexLastLatencySpinFWD
        indexLastLatencySpinTime = indexLastLatencySpinTimeFWD
    } else {
        indexLastLatencySpin = indexLastLatencySpinREV
        indexLastLatencySpinTime = indexLastLatencySpinTimeREV
    }

    oldspin := fe.Data[indexLastLatencySpin]
    oldtime := fe.Data[indexLastLatencySpinTime].(time.Duration)
    //oldtime = time.Duration(oldtime)

    if oldspin != spin {

        timeDelta := (packettime.Seconds() - oldtime.Seconds()) * 1000
        timestamp := float64(pe.Timestamp.UnixNano())/1e9

        fmt.Printf("LATENCYFLIP Epoch: %.3f Delta: %.3fms\tPort: %5d -> %5d\tspin: %d -> %d\n",
               timestamp,
               timeDelta,
               udp.SrcPort,
               udp.DstPort,
               oldspin,
               spin)

        fe.Data[indexLastLatencySpin] = spin
        fe.Data[indexLastLatencySpinTime] = packettime
    }
               
    return true
}


func (ft *FlowTable) ChainGoFunctions() {
    ft.AddInitialFunction(setUpState)
    ft.AddLayerFunction(printMeasurementByte, layers.LayerTypeUDP)
}
               
