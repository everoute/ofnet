/*
**
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ofctrl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	log "github.com/sirupsen/logrus"
)

type Range [2]uint32

const (
	NxmFieldReg = "NXM_NX_REG"
)

type Packet struct {
	SrcMac     net.HardwareAddr
	DstMac     net.HardwareAddr
	SrcIP      net.IP
	DstIP      net.IP
	IPProtocol uint8
	IPLength   uint16
	IPFlags    uint16
	TTL        uint8
	SrcPort    uint16
	DstPort    uint16
	TCPFlags   uint8
	ICMPType   uint8
	ICMPCode   uint8

	ICMPEchoID  uint16
	ICMPEchoSeq uint16
}

type PacketHeader struct {
	IPHeader   *protocol.IPv4
	TCPHeader  *protocol.TCP
	UDPHeader  *protocol.UDP
	ICMPHeader *protocol.ICMP
	ARPHeader  *protocol.ARP
}

type PacketOut struct {
	InPort  uint32
	OutPort *uint32
	SrcMac  net.HardwareAddr
	DstMac  net.HardwareAddr
	Header  *PacketHeader

	Actions []openflow13.Action
}

// RegField specifies a bit range of a register. regID is the register number, and rng is the range of bits
// taken by the field. The OF client could use a RegField to cache or match varied value.
type RegField struct {
	regID int
	rng   *Range
	name  string
}

// RegMark is a value saved in a RegField. A RegMark is used to indicate the traffic
// has some expected characteristics.
type RegMark struct {
	field *RegField
	value uint32
}

// XXRegField specifies a xxreg with a required bit range.
type XXRegField RegField

// CtMarkField specifies a bit range of a CT mark. rng is the range of bits taken by the field. The OF client could use a
// CtMarkField to cache or match varied value.
type CtMarkField struct {
	rng *Range
}

// CtMark is used to indicate the connection characteristics.
type CtMark struct {
	field *CtMarkField
	value uint32
}

type CtLabel struct {
	rng  *Range
	name string
}

func ConstructPacketOut(packet *Packet) *PacketOut {
	// generate packet Header from Packet definition
	packetOut := new(PacketOut)
	packetOut.SrcMac = packet.SrcMac
	packetOut.DstMac = packet.DstMac
	packetOut.Header = new(PacketHeader)
	packetOut.Header.IPHeader = new(protocol.IPv4)
	packetOut.Header.IPHeader.Version = 4
	packetOut.Header.IPHeader.Flags = packet.IPFlags
	packetOut.Header.IPHeader.NWSrc = packet.SrcIP
	packetOut.Header.IPHeader.NWDst = packet.DstIP
	packetOut.Header.IPHeader.TTL = packet.TTL
	//packetOut.Header.IPHeader.IHL = 5

	switch packet.IPProtocol {
	case protocol.Type_ICMP:
		packetOut.Header.ICMPHeader = new(protocol.ICMP)
		packetOut.Header.ICMPHeader.Type = packet.ICMPType
		packetOut.Header.ICMPHeader.Code = packet.ICMPCode
	case protocol.Type_TCP:
		packetOut.Header.TCPHeader = new(protocol.TCP)
		packetOut.Header.TCPHeader.Code = packet.TCPFlags
		packetOut.Header.TCPHeader.PortSrc = packet.SrcPort
		packetOut.Header.TCPHeader.PortDst = packet.DstPort
	case protocol.Type_UDP:
		packetOut.Header.UDPHeader = new(protocol.UDP)
		packetOut.Header.UDPHeader.PortSrc = packet.SrcPort
		packetOut.Header.UDPHeader.PortDst = packet.DstPort
	default:
		log.Infof("unsupport protocol")
	}

	return packetOut
}

func SendPacket(sw *OFSwitch, packetOut *PacketOut) error {
	// generate openflow packetOut from ofctrl packet out
	ofPacketOut := openflow13.NewPacketOut()
	ofPacketOut.InPort = packetOut.InPort

	ofPacketOut.Data = GeneratePacketOutData(packetOut)
	for _, action := range packetOut.Actions {
		ofPacketOut.AddAction(action)
	}
	if packetOut.OutPort != nil {
		log.Infof("send packet to port %v", *packetOut.OutPort)
		ofPacketOut.AddAction(openflow13.NewActionOutput(*packetOut.OutPort))
	} else {
		// default send packet to first table. openflow13 spec defined
		ofPacketOut.AddAction(openflow13.NewActionOutput(openflow13.P_TABLE))
	}
	for _, action := range ofPacketOut.Actions {
		log.Infof("send packetout action %v", action)
	}

	sw.Send(ofPacketOut)

	return nil
}

func GeneratePacketOutData(p *PacketOut) *protocol.Ethernet {
	ethPacket := &protocol.Ethernet{
		HWDst: p.DstMac,
		HWSrc: p.SrcMac,
	}

	switch {
	case p.Header.TCPHeader != nil:
		p.Header.IPHeader.Protocol = protocol.Type_TCP
		p.Header.TCPHeader.HdrLen = 5
		// #nosec G404: random number generator not used for security purposes
		p.Header.TCPHeader.SeqNum = rand.Uint32()
		//if p.Header.TCPHeader.AckNum == 0 {
		//	// #nosec G404: random number generator not used for security purposes
		//	p.Header.TCPHeader.AckNum = rand.Uint32()
		//}
		p.Header.TCPHeader.Checksum = p.tcpHeaderChecksum()
		p.Header.IPHeader.Length = 20 + p.Header.TCPHeader.Len()
		p.Header.IPHeader.Checksum = p.ipHeaderChecksum()
		p.Header.IPHeader.Data = p.Header.TCPHeader
	case p.Header.UDPHeader != nil:
		p.Header.IPHeader.Protocol = protocol.Type_UDP
		p.Header.UDPHeader.Length = p.Header.UDPHeader.Len()
		p.Header.UDPHeader.Checksum = p.udpHeaderChecksum()
		p.Header.IPHeader.Length = 20 + p.Header.UDPHeader.Len()
		p.Header.IPHeader.Checksum = p.ipHeaderChecksum()
		p.Header.IPHeader.Data = p.Header.UDPHeader
	case p.Header.ICMPHeader != nil:
		p.Header.IPHeader.Protocol = protocol.Type_ICMP
		p.setICMPData()
		p.Header.ICMPHeader.Checksum = p.icmpHeaderChecksum()
		p.Header.IPHeader.Length = 20 + p.Header.ICMPHeader.Len()
		p.Header.IPHeader.Checksum = p.ipHeaderChecksum()
		p.Header.IPHeader.Data = p.Header.ICMPHeader
	}
	ethPacket.Ethertype = protocol.IPv4_MSG
	ethPacket.Data = p.Header.IPHeader

	return ethPacket
}

func (p *PacketOut) ipHeaderChecksum() uint16 {
	ipHeader := p.Header.IPHeader
	ipHeader.Checksum = 0
	ipHeader.Data = nil
	data, _ := ipHeader.MarshalBinary()
	return checksum(data)
}

func (p *PacketOut) tcpHeaderChecksum() uint16 {
	tcpHeader := p.Header.TCPHeader
	tcpHeader.Checksum = 0
	data, _ := tcpHeader.MarshalBinary()
	checksumData := append(p.generatePseudoHeader(uint16(len(data))), data...)
	return checksum(checksumData)
}

func (p *PacketOut) setICMPData() {
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data, 0)
	binary.BigEndian.PutUint16(data[2:], 0)
	data = append(data, p.Header.ICMPHeader.Data...)
	p.Header.ICMPHeader.Data = data
}

func (p *PacketOut) icmpHeaderChecksum() uint16 {
	icmpHeader := p.Header.ICMPHeader
	icmpHeader.Checksum = 0
	data, _ := icmpHeader.MarshalBinary()
	checksumData := data
	return checksum(checksumData)
}

func (p *PacketOut) udpHeaderChecksum() uint16 {
	udpHeader := p.Header.UDPHeader
	udpHeader.Checksum = 0
	data, _ := udpHeader.MarshalBinary()
	checksumData := append(p.generatePseudoHeader(uint16(len(data))), data...)
	checksum := checksum(checksumData)
	// From RFC 768:
	// If the computed checksum is zero, it is transmitted as all ones (the
	// equivalent in one's complement arithmetic). An all zero transmitted
	// checksum value means that the transmitter generated no checksum (for
	// debugging or for higher level protocols that don't care).
	if checksum == 0 {
		checksum = 0xffff
	}
	return checksum
}

func (p *PacketOut) generatePseudoHeader(length uint16) []byte {
	var pseudoHeader []byte
	pseudoHeader = make([]byte, 12)
	copy(pseudoHeader[0:4], p.Header.IPHeader.NWSrc.To4())
	copy(pseudoHeader[4:8], p.Header.IPHeader.NWDst.To4())
	pseudoHeader[8] = 0x0
	pseudoHeader[9] = p.Header.IPHeader.Protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], length)
	return pseudoHeader
}

func checksum(data []byte) uint16 {
	sum := uint32(0)
	for ; len(data) >= 2; data = data[2:] {
		sum += uint32(data[0])<<8 | uint32(data[1])
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func (p *PacketIn) GetMatches() *Matchers {
	matches := make([]*MatchField, 0, len(p.Match.Fields))
	for i := range p.Match.Fields {
		matches = append(matches, NewMatchField(&p.Match.Fields[i]))
	}
	return &Matchers{matches: matches}
}

func NewRegField(id int, start, end uint32, name string) *RegField {
	return &RegField{regID: id, rng: &Range{start, end}, name: name}
}

func (f *RegField) GetNXFieldName() string {
	return fmt.Sprintf("%s%d", NxmFieldReg, f.regID)
}

func GetMatchRegField(matchers *Matchers, field *RegField) *MatchField {
	return matchers.GetMatchByName(field.GetNXFieldName())
}

func GetRegValue(regMatch *MatchField, rng *openflow13.NXRange) (uint32, error) {
	regValue, ok := regMatch.GetValue().(*NXRegister)
	if !ok {
		return 0, errors.New("register value cannot be got")
	}
	if rng != nil {
		return GetUint32ValueWithRange(regValue.Data, rng), nil
	}
	return regValue.Data, nil
}

func GenerateTCPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort, srcPort uint16, tcpFlags *uint8) *PacketOut {
	tcpHeader := GenerateTCPHeader(dstPort, srcPort, tcpFlags)
	var pktOut *PacketOut
	ipHeader := &protocol.IPv4{
		Version:        4,
		IHL:            5,
		Length:         20 + tcpHeader.Len(),
		Id:             uint16(rand.Int()),
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       protocol.Type_TCP,
		Checksum:       0,
		NWSrc:          srcIP,
		NWDst:          dstIP,
	}

	packetOutHeader := &PacketHeader{
		IPHeader:  ipHeader,
		TCPHeader: tcpHeader,
	}
	pktOut = &PacketOut{
		SrcMac: srcMAC,
		DstMac: dstMAC,
		Header: packetOutHeader,
	}

	return pktOut
}

func GenerateSimpleIPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) *PacketOut {
	icmpHeader := GenerateICMPHeader(nil, nil)
	ipHeader := &protocol.IPv4{
		Version:        4,
		IHL:            5,
		Length:         20 + icmpHeader.Len(),
		Id:             uint16(rand.Int()),
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       protocol.Type_ICMP,
		Checksum:       0,
		NWSrc:          srcIP,
		NWDst:          dstIP,
	}

	packetOutHeader := &PacketHeader{
		IPHeader:   ipHeader,
		ICMPHeader: icmpHeader,
	}
	pktOut := &PacketOut{
		SrcMac: srcMAC,
		DstMac: dstMAC,
		Header: packetOutHeader,
	}
	return pktOut
}

func GenerateTCPHeader(dstPort, srcPort uint16, flags *uint8) *protocol.TCP {
	header := protocol.NewTCP()
	if dstPort != 0 {
		header.PortDst = dstPort
	} else {
		header.PortDst = uint16(rand.Uint32())
	}
	if srcPort != 0 {
		header.PortSrc = srcPort
	} else {
		header.PortSrc = uint16(rand.Uint32())
	}
	header.AckNum = rand.Uint32()
	header.AckNum = header.AckNum + 1
	header.HdrLen = 20
	if flags != nil {
		header.Code = *flags
	} else {
		header.Code = uint8(1 << 1)
	}
	return header
}

func GenerateICMPHeader(icmpType, icmpCode *uint8) *protocol.ICMP {
	header := protocol.NewICMP()
	if icmpType != nil {
		header.Type = *icmpType
	} else {
		header.Type = 8
	}
	if icmpCode != nil {
		header.Code = *icmpCode
	} else {
		header.Code = 0
	}
	identifier := uint16(rand.Uint32())
	seq := uint16(1)
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data, identifier)
	binary.BigEndian.PutUint16(data[2:], seq)
	return header
}
