package mokumokuren

// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
// Copyright 2017 Brian Trammell. All Rights Reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket/layers"
)

//******************************************************************************
//
// QUIC Decoding Layer
// ------------------------------------------
// This file provides a GoPacket decoding layer for QUIC.
// It follows the First Implementation Draft version of the protocol
// as documented in draft-ietf-quic-protocol-04.
//
//******************************************************************************
//

var NotUDP443 error
var QUICHeaderTruncated error

func init() {
	NotUDP443 = errors.New("I don't think this is a QUIC packet")
	QUICHeaderTruncated = errors.New("The UDP payload does not contain a complete QUIC header")
}

// QUIC header packet types
const (
	QUICPktTypeShortP0P1            = 0x01
	QUICPktTypeShortP0P2            = 0x02
	QUICPktTypeShortP0P4            = 0x03
	QUICPktTypeShortP1P1            = 0x21
	QUICPktTypeShortP1P2            = 0x22
	QUICPktTypeShortP1P4            = 0x23
	QUICPktTypeShortCidP0P1         = 0x41
	QUICPktTypeShortCidP0P2         = 0x42
	QUICPktTypeShortCidP0P4         = 0x43
	QUICPktTypeShortCidP1P1         = 0x61
	QUICPktTypeShortCidP1P2         = 0x62
	QUICPktTypeShortCidP1P4         = 0x63
	QUICPktTypeVersionNego          = 0x81
	QUICPktTypeClientInitial        = 0x82
	QUICPktTypeServerStatelessRetry = 0x83
	QUICPktTypeServerCleartext      = 0x84
	QUICPktTypeClientCleartext      = 0x85
	QUICPktTypeLongZeroRtt          = 0x86
)

var quicPayloadOffset = map[byte]int{
	QUICPktTypeShortP0P1:            2,
	QUICPktTypeShortP0P2:            3,
	QUICPktTypeShortP0P4:            5,
	QUICPktTypeShortP1P1:            2,
	QUICPktTypeShortP1P2:            3,
	QUICPktTypeShortP1P4:            5,
	QUICPktTypeShortCidP0P1:         10,
	QUICPktTypeShortCidP0P2:         11,
	QUICPktTypeShortCidP0P4:         13,
	QUICPktTypeShortCidP1P1:         10,
	QUICPktTypeShortCidP1P2:         11,
	QUICPktTypeShortCidP1P4:         13,
	QUICPktTypeVersionNego:          17,
	QUICPktTypeClientInitial:        17,
	QUICPktTypeServerStatelessRetry: 17,
	QUICPktTypeServerCleartext:      17,
	QUICPktTypeClientCleartext:      17,
	QUICPktTypeLongZeroRtt:          17,
}

var quicCIDOffset = map[byte]int{
	QUICPktTypeShortP0P1:            0,
	QUICPktTypeShortP0P2:            0,
	QUICPktTypeShortP0P4:            0,
	QUICPktTypeShortP1P1:            0,
	QUICPktTypeShortP1P2:            0,
	QUICPktTypeShortP1P4:            0,
	QUICPktTypeShortCidP0P1:         1,
	QUICPktTypeShortCidP0P2:         1,
	QUICPktTypeShortCidP0P4:         1,
	QUICPktTypeShortCidP1P1:         1,
	QUICPktTypeShortCidP1P2:         1,
	QUICPktTypeShortCidP1P4:         1,
	QUICPktTypeVersionNego:          1,
	QUICPktTypeClientInitial:        1,
	QUICPktTypeServerStatelessRetry: 1,
	QUICPktTypeServerCleartext:      1,
	QUICPktTypeClientCleartext:      1,
	QUICPktTypeLongZeroRtt:          1,
}

var quicVNOffset = map[byte]int{
	QUICPktTypeShortP0P1:            0,
	QUICPktTypeShortP0P2:            0,
	QUICPktTypeShortP0P4:            0,
	QUICPktTypeShortP1P1:            0,
	QUICPktTypeShortP1P2:            0,
	QUICPktTypeShortP1P4:            0,
	QUICPktTypeShortCidP0P1:         0,
	QUICPktTypeShortCidP0P2:         0,
	QUICPktTypeShortCidP0P4:         0,
	QUICPktTypeShortCidP1P1:         0,
	QUICPktTypeShortCidP1P2:         0,
	QUICPktTypeShortCidP1P4:         0,
	QUICPktTypeVersionNego:          13,
	QUICPktTypeClientInitial:        13,
	QUICPktTypeServerStatelessRetry: 13,
	QUICPktTypeServerCleartext:      13,
	QUICPktTypeClientCleartext:      13,
	QUICPktTypeLongZeroRtt:          13,
}

var quicPNOffset = map[byte]int{
	QUICPktTypeShortP0P1:            1,
	QUICPktTypeShortP0P2:            1,
	QUICPktTypeShortP0P4:            1,
	QUICPktTypeShortP1P1:            1,
	QUICPktTypeShortP1P2:            1,
	QUICPktTypeShortP1P4:            1,
	QUICPktTypeShortCidP0P1:         9,
	QUICPktTypeShortCidP0P2:         9,
	QUICPktTypeShortCidP0P4:         9,
	QUICPktTypeShortCidP1P1:         9,
	QUICPktTypeShortCidP1P2:         9,
	QUICPktTypeShortCidP1P4:         9,
	QUICPktTypeVersionNego:          9,
	QUICPktTypeClientInitial:        9,
	QUICPktTypeServerStatelessRetry: 9,
	QUICPktTypeServerCleartext:      9,
	QUICPktTypeClientCleartext:      9,
	QUICPktTypeLongZeroRtt:          9,
}

var quicPNLength = map[byte]int{
	QUICPktTypeShortP0P1:            1,
	QUICPktTypeShortP0P2:            2,
	QUICPktTypeShortP0P4:            4,
	QUICPktTypeShortP1P1:            1,
	QUICPktTypeShortP1P2:            2,
	QUICPktTypeShortP1P4:            4,
	QUICPktTypeShortCidP0P1:         1,
	QUICPktTypeShortCidP0P2:         2,
	QUICPktTypeShortCidP0P4:         4,
	QUICPktTypeShortCidP1P1:         1,
	QUICPktTypeShortCidP1P2:         2,
	QUICPktTypeShortCidP1P4:         4,
	QUICPktTypeVersionNego:          4,
	QUICPktTypeClientInitial:        4,
	QUICPktTypeServerStatelessRetry: 4,
	QUICPktTypeServerCleartext:      4,
	QUICPktTypeClientCleartext:      4,
	QUICPktTypeLongZeroRtt:          4,
}

var quicKeyPhase = map[byte]int{
	QUICPktTypeShortP0P1:            0,
	QUICPktTypeShortP0P2:            0,
	QUICPktTypeShortP0P4:            0,
	QUICPktTypeShortP1P1:            1,
	QUICPktTypeShortP1P2:            1,
	QUICPktTypeShortP1P4:            1,
	QUICPktTypeShortCidP0P1:         0,
	QUICPktTypeShortCidP0P2:         0,
	QUICPktTypeShortCidP0P4:         0,
	QUICPktTypeShortCidP1P1:         1,
	QUICPktTypeShortCidP1P2:         1,
	QUICPktTypeShortCidP1P4:         1,
	QUICPktTypeVersionNego:          -1,
	QUICPktTypeClientInitial:        -1,
	QUICPktTypeServerStatelessRetry: -1,
	QUICPktTypeServerCleartext:      -1,
	QUICPktTypeClientCleartext:      -1,
	QUICPktTypeLongZeroRtt:          -1,
}

// A QUIC packet header or QUIC special packet
type QUICHeader struct {
	PktType   byte   // packet type, not decoded
	ConnID    uint64 // Connection ID
	PktNum    uint32 // Packet Number
	PktNumLen int    // Length of packet number on wire
	Version   uint32 // Version number for VN packets
	KeyPhase  int    // Key phase for short packets

	payload []byte
}

func (q *QUICHeader) ExtractFromUDP(udp *layers.UDP) error {
	// if it ain't UDP/443, it ain't QUIC
	if udp.DstPort != 443 && udp.SrcPort != 443 {
		return NotUDP443
	}

	data := udp.Payload

	// min quic header size is 2
	if len(data) < 2 {
		return QUICHeaderTruncated
	}

	// switch on header type
	q.PktType = data[0]

	// find payload offset and snarf payload
	payoff, ok := quicPayloadOffset[q.PktType]
	if !ok {
		return fmt.Errorf("Unknown QUIC packet type %d", q.PktType)
	}
	q.payload = data[payoff:]

	// unpack quic header
	cidoffset := quicCIDOffset[q.PktType]
	if cidoffset > 0 {
		if len(data) < cidoffset+8 {
			return QUICHeaderTruncated
		}
		q.ConnID = binary.BigEndian.Uint64(data[cidoffset : cidoffset+8])
	}

	vnoffset := quicVNOffset[q.PktType]
	if vnoffset > 0 {
		if len(data) < vnoffset+4 {
			return QUICHeaderTruncated
		}
		q.Version = binary.BigEndian.Uint32(data[vnoffset : vnoffset+4])
	}

	pnoffset := quicPNOffset[q.PktType]
	q.PktNumLen = quicPNLength[q.PktType]
	if len(data) < pnoffset+q.PktNumLen {
		return QUICHeaderTruncated
	}
	switch q.PktNumLen {
	case 1:
		q.PktNum = uint32(data[pnoffset])
	case 2:
		q.PktNum = uint32(binary.BigEndian.Uint16(data[pnoffset : pnoffset+2]))
	case 4:
		q.PktNum = binary.BigEndian.Uint32(data[pnoffset : pnoffset+4])
	default:
		panic("invariant failed in decoder: illegal packet number length")
	}

	q.KeyPhase = quicKeyPhase[q.PktType]

	return nil
}

// Given a last packet number, decode this packet's encoded packet number as a full packet number
func (q *QUICHeader) FullPacketNumber(last uint64) uint64 {
	switch q.PktNumLen {
	case 1:
		if uint32(last&0xff) > q.PktNum {
			return ((last & 0xffffffffffffff00) + 0x100) | uint64(q.PktNum)
		} else {
			return (last & 0xffffffffffffff00) | uint64(q.PktNum)
		}
	case 2:
		if uint32(last&0xffff) > q.PktNum {
			return ((last & 0xffffffffffff0000) + 0x10000) | uint64(q.PktNum)
		} else {
			return (last & 0xffffffffffff0000) | uint64(q.PktNum)
		}
	case 4:
		if uint32(last&0xffffffff) > q.PktNum {
			return ((last & 0xffffffff00000000) + 0x100000000) | uint64(q.PktNum)
		} else {
			return (last & 0xffffffff00000000) | uint64(q.PktNum)
		}
	default:
		panic("invariant failed in decoder: illegal packet number length")
	}
}
