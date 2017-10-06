package mokumokuren

import (
//	"encoding/binary"
//	"log"
//	"strings"
//	"time"
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

func printMeasurementByte(fe *FlowEntry, pe PacketEvent, layer gopacket.Layer) bool {
    time := pe.Timestamp.Sub(fe.StartTime)
    
    udp := layer.(*layers.UDP)
    payload := layer.LayerPayload()
    
    measurement := payload[indexMeasurementByte]
    
    spin := (measurement & (0x01 << bitsetLatencySpin)) >> bitsetLatencySpin
    
    fmt.Printf("Time: %.3fs\tPort: %5d -> %5d\tspin: %d\n", 
               time.Seconds(),
               udp.SrcPort,
               udp.DstPort,
               spin)
               
    return true
}


func (ft *FlowTable) ChainGoFunctions() {
    ft.AddLayerFunction(printMeasurementByte, layers.LayerTypeUDP)
}
               
