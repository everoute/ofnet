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

// This file implements the forwarding graph API for the flow

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/contiv/libOpenflow/openflow13"
	log "github.com/sirupsen/logrus"

	"github.com/contiv/ofnet/ofctrl/dperror"
)

// Small subset of openflow fields we currently support
type FlowMatch struct {
	Priority       uint16            // Priority of the flow
	InputPort      uint32            // Input port number
	MacDa          *net.HardwareAddr // Mac dest
	MacDaMask      *net.HardwareAddr // Mac dest mask
	MacSa          *net.HardwareAddr // Mac source
	MacSaMask      *net.HardwareAddr // Mac source mask
	Ethertype      uint16            // Ethertype
	VlanId         uint16            // vlan id
	VlanIdMask     *uint16           // vlan id mask
	ArpOper        uint16            // ARP Oper type
	ArpTpa         *net.IP           // Arp Tpa (target IP)
	ArpTpaMask     *net.IP           // Mask for Arp Tpa
	ArpSpa         *net.IP           // Arp Spa (source IP)
	ArpSpaMask     *net.IP           // Mask for Arp Spa
	IpSa           *net.IP           // IPv4 source addr
	IpSaMask       *net.IP           // IPv4 source mask
	IpDa           *net.IP           // IPv4 dest addr
	IpDaMask       *net.IP           // IPv4 dest mask
	Ipv6Sa         *net.IP           // IPv6 source addr
	Ipv6SaMask     *net.IP           // IPv6 source mask
	Ipv6Da         *net.IP           // IPv6 dest addr
	Ipv6DaMask     *net.IP           // IPv6 dest mask
	IpProto        uint8             // IP protocol
	IcmpCode       uint8             // ICMP code
	IcmpType       uint8             // ICMP type
	IpDscp         uint8             // DSCP/TOS field
	TcpSrcPort     uint16            // TCP source port
	TcpSrcPortMask uint16            // TCP source port mask
	TcpDstPort     uint16            // TCP dest port
	TcpDstPortMask uint16            // TCP dest port mask
	UdpSrcPort     uint16            // UDP source port
	UdpSrcPortMask uint16            // UDP source port mask
	UdpDstPort     uint16            // UDP dest port
	UdpDstPortMask uint16            // UDP dest port mask
	Metadata       *uint64           // OVS metadata
	MetadataMask   *uint64           // Metadata mask
	TunnelId       uint64            // Vxlan Tunnel id i.e. VNI
	TcpFlags       *uint16           // TCP flags
	TcpFlagsMask   *uint16           // Mask for TCP flags

	CtStates    *openflow13.CTStates
	CTLabel     *[16]byte
	CTLabelMask *[16]byte
	PktMark     uint32 // NXM_NX_PKT_MARK field, in linux kernel, from skb_mark
	PktMarkMask *uint32
	Regs        []*NXRegister // NXM_NX_REGX[]
}

// NXM_NX_REGX (X in 0~15) register match field
type NXRegister struct {
	RegID int                 // register id
	Data  uint32              // register data
	Range *openflow13.NXRange // register range selection mask
}

func (f *Flow) SendToController(controllerAction *NXController) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, controllerAction)

	return nil
}

func (f *Flow) NewControllerAction(controllerID uint16, reason uint8) *NXController {
	return NewControllerAction(controllerID, reason)
}

func (f *Flow) Output(outputAction *OutputAction) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, outputAction)

	return nil
}

func (f *Flow) MoveField(bitLen, srcOffset, dstOffset uint16, srcMatchFieldName, dstMatchFieldName string, hasMask bool) error {
	moveAct, err := NewNXMoveAction(bitLen, srcOffset, dstOffset, srcMatchFieldName, dstMatchFieldName, hasMask)
	if err != nil {
		return err
	}
	if srcMatchFieldName == "nxm_nx_tun_metadata0" {
		f.Table.Switch.ResetFieldLength(moveAct.SrcField)
	}
	if dstMatchFieldName == "nxm_nx_tun_metadata0" {
		f.Table.Switch.ResetFieldLength(moveAct.DstField)
	}

	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, moveAct)
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) LoadField(fieldName string, data uint64, dataRange *openflow13.NXRange) error {
	loadAct, err := NewNXLoadAction(fieldName, data, dataRange)
	if err != nil {
		return err
	}
	if fieldName == "nxm_nx_tun_metadata0" {
		f.Table.Switch.ResetFieldLength(loadAct.Field)
	}

	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, loadAct)
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) AppendedLoadField(fieldName string, data uint64, dataRange *openflow13.NXRange) error {
	loadAct, err := NewAppendedNXLoadAction(fieldName, data, dataRange)
	if err != nil {
		return err
	}
	if fieldName == "nxm_nx_tun_metadata0" {
		f.Table.Switch.ResetFieldLength(loadAct.Field)
	}

	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, loadAct)
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) Resubmit(inPort *uint16, tableId *uint8) error {
	action := NewResubmitAction(inPort, tableId)

	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, action)
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) Learn(learnAction *LearnAction) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, learnAction)
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) DecNwTtl() error {
	action := NewDecNwTtlAction(ActTypeDecNwTtl)
	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, action)

	return nil
}

// State of a flow entry
type Flow struct {
	Table       *Table       // Table where this flow resides
	Match       FlowMatch    // Fields to be matched
	NextElem    FgraphElem   // Next fw graph element
	isInstalled bool         // Is the flow installed in the switch
	FlowID      uint64       // Unique ID for the flow
	flowActions []Action     // List of flow actions
	lock        sync.RWMutex // lock for modifying flow state
}

const IP_PROTO_TCP = 6
const IP_PROTO_UDP = 17

// string key for the flow
// FIXME: simple json conversion for now. This needs to be smarter
func (self *Flow) FlowKey() string {
	jsonVal, err := json.Marshal(self.Match)
	if err != nil {
		log.Errorf("Error forming flowkey for %+v. Err: %v", self, err)
		return ""
	}

	return string(jsonVal)
}

// Fgraph element type for the flow
func (self *Flow) Type() string {
	return "flow"
}

// instruction set for flow element
func (self *Flow) GetFlowInstr() openflow13.Instruction {
	log.Fatalf("Unexpected call to get flow's instruction set")
	return nil
}

func AddPortMask(field *openflow13.MatchField, portMask uint16) {
	if portMask != 0xffff && portMask != 0x0000 {
		mask := new(openflow13.PortField)
		b := make([]byte, 16)
		binary.BigEndian.PutUint16(b, portMask)
		err := mask.UnmarshalBinary(b)
		if err != nil {
			log.Fatalf("Error addPortMask, wrong portMask:%x, err:%s.", portMask, err)
		}

		field.Mask = mask
		field.HasMask = true
		field.Length += uint8(mask.Len())
	}
}

func AddArpTpaMask(field *openflow13.MatchField, arpTpaMask *net.IP) {
	if arpTpaMask != nil {
		mask := new(openflow13.ArpXPaField)
		mask.ArpPa = *arpTpaMask

		field.Mask = mask
		field.HasMask = true
		field.Length += uint8(mask.Len())
	}
}

func AddArpSpaMask(field *openflow13.MatchField, arpSpaMask *net.IP) {
	if arpSpaMask != nil {
		mask := new(openflow13.ArpXPaField)
		mask.ArpPa = *arpSpaMask

		field.Mask = mask
		field.HasMask = true
		field.Length += uint8(mask.Len())
	}
}

// Translate our match fields into openflow 1.3 match fields
func (self *Flow) xlateMatch() openflow13.Match {
	ofMatch := openflow13.NewMatch()

	// Handle input poty
	if self.Match.InputPort != 0 {
		inportField := openflow13.NewInPortField(self.Match.InputPort)
		ofMatch.AddField(*inportField)
	}

	// Handle mac DA field
	if self.Match.MacDa != nil {
		if self.Match.MacDaMask != nil {
			macDaField := openflow13.NewEthDstField(*self.Match.MacDa, self.Match.MacDaMask)
			ofMatch.AddField(*macDaField)
		} else {
			macDaField := openflow13.NewEthDstField(*self.Match.MacDa, nil)
			ofMatch.AddField(*macDaField)
		}
	}

	// Handle MacSa field
	if self.Match.MacSa != nil {
		if self.Match.MacSaMask != nil {
			macSaField := openflow13.NewEthSrcField(*self.Match.MacSa, self.Match.MacSaMask)
			ofMatch.AddField(*macSaField)
		} else {
			macSaField := openflow13.NewEthSrcField(*self.Match.MacSa, nil)
			ofMatch.AddField(*macSaField)
		}
	}

	// Handle ethertype
	if self.Match.Ethertype != 0 {
		etypeField := openflow13.NewEthTypeField(self.Match.Ethertype)
		ofMatch.AddField(*etypeField)
	}

	// Handle Vlan id
	if self.Match.VlanId != 0 {
		vlanIdField := openflow13.NewVlanIdField(self.Match.VlanId, self.Match.VlanIdMask)
		ofMatch.AddField(*vlanIdField)
	}

	// Handle ARP Oper type
	if self.Match.ArpOper != 0 {
		arpOperField := openflow13.NewArpOperField(self.Match.ArpOper)
		ofMatch.AddField(*arpOperField)
	}

	// Handle ARP tpa
	if self.Match.ArpTpa != nil {
		arpTpaField := openflow13.NewArpTpaField(*self.Match.ArpTpa)
		AddArpTpaMask(arpTpaField, self.Match.ArpTpaMask)
		ofMatch.AddField(*arpTpaField)
	}

	if self.Match.ArpSpa != nil {
		arpSpaField := openflow13.NewArpSpaField(*self.Match.ArpSpa)
		AddArpSpaMask(arpSpaField, self.Match.ArpSpaMask)
		ofMatch.AddField(*arpSpaField)
	}

	// Handle IP Dst
	if self.Match.IpDa != nil {
		if self.Match.IpDaMask != nil {
			ipDaField := openflow13.NewIpv4DstField(*self.Match.IpDa, self.Match.IpDaMask)
			ofMatch.AddField(*ipDaField)
		} else {
			ipDaField := openflow13.NewIpv4DstField(*self.Match.IpDa, nil)
			ofMatch.AddField(*ipDaField)
		}
	}

	// Handle IP Src
	if self.Match.IpSa != nil {
		if self.Match.IpSaMask != nil {
			ipSaField := openflow13.NewIpv4SrcField(*self.Match.IpSa, self.Match.IpSaMask)
			ofMatch.AddField(*ipSaField)
		} else {
			ipSaField := openflow13.NewIpv4SrcField(*self.Match.IpSa, nil)
			ofMatch.AddField(*ipSaField)
		}
	}

	// Handle IPv6 Dst
	if self.Match.Ipv6Da != nil {
		if self.Match.Ipv6DaMask != nil {
			ipv6DaField := openflow13.NewIpv6DstField(*self.Match.Ipv6Da, self.Match.Ipv6DaMask)
			ofMatch.AddField(*ipv6DaField)
		} else {
			ipv6DaField := openflow13.NewIpv6DstField(*self.Match.Ipv6Da, nil)
			ofMatch.AddField(*ipv6DaField)
		}
	}

	// Handle IPv6 Src
	if self.Match.Ipv6Sa != nil {
		if self.Match.Ipv6SaMask != nil {
			ipv6SaField := openflow13.NewIpv6SrcField(*self.Match.Ipv6Sa, self.Match.Ipv6SaMask)
			ofMatch.AddField(*ipv6SaField)
		} else {
			ipv6SaField := openflow13.NewIpv6SrcField(*self.Match.Ipv6Sa, nil)
			ofMatch.AddField(*ipv6SaField)
		}
	}

	// Handle IP protocol
	if self.Match.IpProto != 0 {
		protoField := openflow13.NewIpProtoField(self.Match.IpProto)
		ofMatch.AddField(*protoField)
	}

	// Handle IP dscp
	if self.Match.IpDscp != 0 {
		dscpField := openflow13.NewIpDscpField(self.Match.IpDscp)
		ofMatch.AddField(*dscpField)
	}

	// icmp code and type
	if self.Match.IcmpCode != 0 {
		icmpCodeField := openflow13.NewIcmpCodeField(self.Match.IcmpCode)
		ofMatch.AddField(*icmpCodeField)
	}
	if self.Match.IcmpType != 0 {
		icmpTypeField := openflow13.NewIcmpTypeField(self.Match.IcmpType)
		ofMatch.AddField(*icmpTypeField)
	}

	// Handle port numbers
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpSrcPort != 0 {
		portField := openflow13.NewTcpSrcField(self.Match.TcpSrcPort)
		AddPortMask(portField, self.Match.TcpSrcPortMask)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpDstPort != 0 {
		portField := openflow13.NewTcpDstField(self.Match.TcpDstPort)
		AddPortMask(portField, self.Match.TcpDstPortMask)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_UDP && self.Match.UdpSrcPort != 0 {
		portField := openflow13.NewUdpSrcField(self.Match.UdpSrcPort)
		AddPortMask(portField, self.Match.UdpSrcPortMask)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_UDP && self.Match.UdpDstPort != 0 {
		portField := openflow13.NewUdpDstField(self.Match.UdpDstPort)
		AddPortMask(portField, self.Match.UdpDstPortMask)
		ofMatch.AddField(*portField)
	}

	// Handle tcp flags
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpFlags != nil {
		tcpFlagField := openflow13.NewTcpFlagsField(*self.Match.TcpFlags, self.Match.TcpFlagsMask)
		ofMatch.AddField(*tcpFlagField)
	}

	// Handle metadata
	if self.Match.Metadata != nil {
		if self.Match.MetadataMask != nil {
			metadataField := openflow13.NewMetadataField(*self.Match.Metadata, self.Match.MetadataMask)
			ofMatch.AddField(*metadataField)
		} else {
			metadataField := openflow13.NewMetadataField(*self.Match.Metadata, nil)
			ofMatch.AddField(*metadataField)
		}
	}

	// Handle Vxlan tunnel id
	if self.Match.TunnelId != 0 {
		tunnelIdField := openflow13.NewTunnelIdField(self.Match.TunnelId)
		ofMatch.AddField(*tunnelIdField)
	}

	if self.Match.CtStates != nil {
		ctStateField := openflow13.NewCTStateMatchField(self.Match.CtStates)
		ofMatch.AddField(*ctStateField)
	}

	if self.Match.CTLabel != nil {
		ctLabelField := openflow13.NewCTLabelMatchField(*self.Match.CTLabel, self.Match.CTLabelMask)
		ofMatch.AddField(*ctLabelField)
	}

	// pkt_mark match
	if self.Match.PktMark != 0 {
		pktMarkField, _ := openflow13.FindFieldHeaderByName("NXM_NX_PKT_MARK", self.Match.PktMarkMask != nil)
		pktMarkField.Value = &openflow13.Uint32Message{
			Data: self.Match.PktMark,
		}
		if self.Match.PktMarkMask != nil {
			pktMarkField.Mask = &openflow13.Uint32Message{
				Data: *self.Match.PktMarkMask,
			}
		}
		ofMatch.AddField(*pktMarkField)
	}

	if self.Match.Regs != nil {
		for _, reg := range self.Match.Regs {
			registerField := openflow13.NewRegMatchField(reg.RegID, reg.Data, reg.Range)
			ofMatch.AddField(*registerField)
		}
	}

	return *ofMatch
}

// Install all flow actions
func (self *Flow) installFlowActions(flowMod *openflow13.FlowMod,
	instr openflow13.Instruction) error {
	var actInstr openflow13.Instruction
	var addActn bool = false

	// Create a apply_action instruction to be used if its not already created
	switch instr.(type) {
	case *openflow13.InstrActions:
		actInstr = instr
	default:
		actInstr = openflow13.NewInstrApplyActions()
	}

	// Loop thru all actions
	for _, flowAction := range self.flowActions {
		actType := flowAction.GetActionType()
		switch actType {
		case ActTypeSetVlan:
			// Push Vlan Tag action
			pushVlanAction, _ := NewPushVlanAction(0x8100).ToOfAction()

			// Set Outer vlan tag field
			setVlanAction, _ := flowAction.ToOfAction()

			// Prepend push vlan & setvlan actions to existing instruction
			actInstr.AddAction(setVlanAction, true)
			actInstr.AddAction(pushVlanAction, true)
			addActn = true

			log.Debugf("flow install. Added pushvlan action: %+v, setVlan actions: %+v",
				pushVlanAction, setVlanAction)

		case ActTypeMetatdata:
			act := flowAction.(*SetMetadata)
			// Set Metadata instruction
			metadataInstr := openflow13.NewInstrWriteMetadata(act.metadata, act.metadataMask)

			// Add the instruction to flowmod
			flowMod.AddInstruction(metadataInstr)

		case ActTypePopVlan, ActTypeSetDstMac, ActTypeSetSrcMac, ActTypeSetTunnelID, ActTypeSetSrcIP, ActTypeSetDstIP,
			ActTypeSetDSCP, ActTypeSetTCPsPort, ActTypeSetTCPdPort, ActTypeSetUDPdPort, ActTypeSetUDPsPort, ActTypeNXLoad,
			ActTypeNXMove, ActTypeNXLearn, ActTypeDecNwTtl:

			var prepend bool = true
			act, _ := flowAction.ToOfAction()
			if flowAction.GetActionType() == ActTypeNXLoad && flowAction.(*NXLoadAction).Appended {
				// prepend instruction to openflow act set
				prepend = false
			}
			// Add it to instruction
			err := actInstr.AddAction(act, prepend)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added %s action: %+v", actType, act)

		case ActTypeNXResubmit, ActTypeOutput, ActTypeController, ActTypeGroup, ActTypeCT:
			act, _ := flowAction.ToOfAction()
			err := actInstr.AddAction(act, false)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("Add %s action: %v", actType, act)

		default:
			log.Fatalf("Unknown action type %s", actType)
		}
	}

	// Add the instruction to flow if its not already added
	if (addActn) && (actInstr != instr) {
		// Add the instrction to flowmod
		flowMod.AddInstruction(actInstr)
	}

	return nil
}

// Install a flow entry
func (self *Flow) install() error {
	// Create a flowmode entry
	flowMod := openflow13.NewFlowMod()
	flowMod.TableId = self.Table.TableId
	flowMod.Priority = self.Match.Priority
	flowMod.Cookie = self.FlowID
	flowMod.CookieMask = uint64(0xffffffffffffffff)

	// Add or modify
	if !self.isInstalled {
		flowMod.Command = openflow13.FC_ADD
	} else {
		flowMod.Command = openflow13.FC_MODIFY
	}

	// convert match fields to openflow 1.3 format
	flowMod.Match = self.xlateMatch()
	log.Debugf("flow install: Match: %+v", flowMod.Match)

	// Based on the next elem, decide what to install
	switch self.NextElem.Type() {
	case "table":
		// Get the instruction set from the element
		instr := self.NextElem.GetFlowInstr()

		// Check if there are any flow actions to perform
		self.installFlowActions(flowMod, instr)

		// Add the instruction to flowmod
		flowMod.AddInstruction(instr)

		log.Debugf("flow install: added goto table instr: %+v", instr)

	case "flood":
		fallthrough
	case "output":
		// Get the instruction set from the element
		instr := self.NextElem.GetFlowInstr()

		// Add the instruction to flowmod if its not nil
		// a nil instruction means drop action
		if instr != nil {

			// Check if there are any flow actions to perform
			self.installFlowActions(flowMod, instr)

			flowMod.AddInstruction(instr)

			log.Debugf("flow install: added output port instr: %+v", instr)
		}
	case "group":
		fallthrough
	case "empty":
		instr := self.NextElem.GetFlowInstr()
		if instr != nil {
			err := self.installFlowActions(flowMod, instr)
			if err != nil {
				return err
			}
			if len(instr.(*openflow13.InstrActions).Actions) > 0 {
				flowMod.AddInstruction(instr)
			}
		}

		log.Debugf("flow install: added empty forwarding elem %v", instr)
	default:
		log.Fatalf("Unknown Fgraph element type %s", self.NextElem.Type())
	}

	log.Debugf("Sending flowmod: %+v", flowMod)

	// Send the message
	if self.Table.Switch == nil {
		return dperror.NewDpError(dperror.SwitchDisconnectedError.Code, dperror.SwitchDisconnectedError.Msg, fmt.Errorf("ofSwitch disconnected"))
	}
	self.Table.Switch.Send(flowMod)

	// Mark it as installed
	self.isInstalled = true

	return nil
}

// Set Next element in the Fgraph. This determines what actions will be
// part of the flow's instruction set
func (self *Flow) Next(elem FgraphElem) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Set the next element in the graph
	self.NextElem = elem

	// Install the flow entry
	return self.install()
}

func (self *Flow) SetConntrack(connTrackAction *ConnTrackAction) error {
	self.flowActions = append(self.flowActions, connTrackAction)

	return nil
}

// Special actions on the flow to set vlan id
func (self *Flow) SetVlan(vlanId uint16) error {
	action := NewSetVlanAction(vlanId)

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set vlan id
func (self *Flow) PopVlan() error {
	action := NewPopVlanAction()

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set mac dest addr
func (self *Flow) SetMacDa(macDa net.HardwareAddr) error {
	action := NewSetDstMac(macDa)

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special action on the flow to set mac source addr
func (self *Flow) SetMacSa(macSa net.HardwareAddr) error {
	action := NewSetSrcMac(macSa)

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special action on the flow to set an ip field
func (self *Flow) SetIPField(ip net.IP, field string) error {
	var action Action
	if field == "Src" {
		action = NewSetSrcIP(ip)
	} else if field == "Dst" {
		action = NewSetDstIP(ip)
	} else {
		return errors.New("field not supported")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special action on the flow to set a L4 field
func (self *Flow) SetL4Field(port uint16, field string) error {
	var action Action

	switch field {
	case "TCPSrc":
		action = NewSetTCPSrc(port)
		break
	case "TCPDst":
		action = NewSetTCPDst(port)
		break
	case "UDPSrc":
		action = NewSetUDPSrc(port)
		break
	case "UDPDst":
		action = NewSetUDPDst(port)
		break
	default:
		return errors.New("field not supported")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set metadata
func (self *Flow) SetMetadata(metadata, metadataMask uint64) error {
	action := NewSetMetadata(metadata, metadataMask)

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set vlan id
func (self *Flow) SetTunnelId(tunnelId uint64) error {
	action := NewSetTunnelID(tunnelId)

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set group
func (self *Flow) SetGroup(groupID uint32) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	self.flowActions = append(self.flowActions, NewGroupAction(groupID))

	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set dscp field
func (self *Flow) SetDscp(dscp uint8) error {
	action := NewSetDscp(dscp)

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// unset dscp field
func (self *Flow) UnsetDscp() error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Delete to the action from db
	for idx, act := range self.flowActions {
		if act.GetActionType() == ActTypeSetDSCP {
			self.flowActions = append(self.flowActions[:idx], self.flowActions[idx+1:]...)
		}
	}

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Delete the flow
func (self *Flow) Delete() error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Delete from ofswitch
	if self.isInstalled {
		// Create a flowmode entry
		flowMod := openflow13.NewFlowMod()
		flowMod.Command = openflow13.FC_DELETE
		flowMod.TableId = self.Table.TableId
		flowMod.Priority = self.Match.Priority
		flowMod.Cookie = self.FlowID
		flowMod.CookieMask = uint64(0xffffffffffffffff)
		flowMod.OutPort = openflow13.P_ANY
		flowMod.OutGroup = openflow13.OFPG_ANY

		log.Debugf("Sending DELETE flowmod: %+v", flowMod)

		// Send the message
		if self.Table.Switch == nil {
			return dperror.NewDpError(dperror.SwitchDisconnectedError.Code, dperror.SwitchDisconnectedError.Msg, fmt.Errorf("ofSwitch disconnected"))
		}
		self.Table.Switch.Send(flowMod)
	}

	return nil
}

func DeleteFlow(table *Table, priority uint16, flowID uint64) error {
	// Create a flow mode entry
	flowMod := openflow13.NewFlowMod()
	flowMod.Command = openflow13.FC_DELETE
	flowMod.TableId = table.TableId
	flowMod.Priority = priority
	flowMod.Cookie = flowID
	flowMod.CookieMask = uint64(0xffffffffffffffff)
	flowMod.OutPort = openflow13.P_ANY
	flowMod.OutGroup = openflow13.OFPG_ANY

	log.Debugf("Sending DELETE flow mod: %+v", flowMod)

	// Send the message
	if table.Switch == nil {
		return dperror.NewDpError(dperror.SwitchDisconnectedError.Code, dperror.SwitchDisconnectedError.Msg, fmt.Errorf("ofSwitch disconnected"))
	}
	table.Switch.Send(flowMod)

	return nil
}

func InstallFlow(flow *Flow) error {
	return flow.install()
}
