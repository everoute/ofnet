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
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ovsdbDriver"
	log "github.com/sirupsen/logrus"
)

type OfActor struct {
	Switch            *OFSwitch
	isSwitchConnected bool

	inputTable *Table
	nextTable  *Table
}

func (o *OfActor) PacketRcvd(sw *OFSwitch, packet *PacketIn) {
	log.Printf("App: Received packet: %+v", packet)
}

func (o *OfActor) SwitchConnected(sw *OFSwitch) {
	log.Printf("App: Switch connected: %v", sw.DPID())

	// Store switch for later use
	o.Switch = sw

	o.isSwitchConnected = true
}

func (o *OfActor) MultipartReply(sw *OFSwitch, rep *openflow13.MultipartReply) {
}

func (o *OfActor) SwitchDisconnected(sw *OFSwitch) {
	log.Printf("App: Switch disconnected: %v", sw.DPID())
}

var ofActor OfActor
var ctrler *Controller
var ovsDriver *ovsdbDriver.OvsDriver

// Run an ovs-ofctl command
func runOfctlCmd(cmd, brName string, args ...string) ([]byte, error) {
	var cmdStr string
	if len(args) == 0 {
		cmdStr = fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 %s %s", cmd, brName)
	} else if len(args) == 1 {
		cmdStr = fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 %s %s %s", cmd, brName, args[0])
	} else {
		return nil, errors.New("error params")
	}

	out, err := exec.Command("/bin/sh", "-c", cmdStr).Output()
	if err != nil {
		log.Errorf("error running ovs-ofctl %s %s. Error: %v", cmd, brName, err)
		return nil, err
	}

	return out, nil
}

// dump the flows and parse the Output
func ofctlFlowDump(brName string) ([]string, error) {
	flowDump, err := runOfctlCmd("dump-flows", brName)
	if err != nil {
		log.Errorf("Error running dump-flows on %s. Err: %v", brName, err)
		return nil, err
	}

	log.Debugf("Flow dump: %s", flowDump)
	flowOutStr := string(flowDump)
	flowDb := strings.Split(flowOutStr, "\n")[1:]

	log.Debugf("flowDb: %+v", flowDb)

	var flowList []string
	for _, flow := range flowDb {
		felem := strings.Fields(flow)
		if len(felem) > 2 {
			felem = append(felem[:1], felem[2:]...)
			felem = append(felem[:2], felem[4:]...)
			fstr := strings.Join(felem, " ")
			flowList = append(flowList, fstr)
		}
	}

	log.Infof("flowList: %+v", flowList)

	return flowList, nil
}

// Find a flow in flow list and match its action
func ofctlFlowMatch(flowList []string, tableId int, matchStr, actStr string) bool {
	mtStr := fmt.Sprintf("table=%d, %s ", tableId, matchStr)
	aStr := fmt.Sprintf("actions=%s", actStr)
	for _, flowEntry := range flowList {
		log.Debugf("Looking for %s %s in %s", mtStr, aStr, flowEntry)
		if strings.Contains(flowEntry, mtStr) && strings.Contains(flowEntry, aStr) {
			return true
		}
	}

	return false
}

func ofctlFlowMatchCookieID(flowList []string, cookieID uint64) bool {
	mStr := fmt.Sprintf("cookie=%#x", cookieID)
	for _, flowEntry := range flowList {
		if strings.Contains(flowEntry, mStr) {
			return true
		}
	}
	return false
}

// ofctlDumpFlowMatch dumps flows and finds a match
func ofctlDumpFlowMatch(brName string, tableId int, matchStr, actStr string) bool {
	// dump flows
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		log.Errorf("Error dumping flows: Err %v", err)
		return false
	}

	return ofctlFlowMatch(flowList, tableId, matchStr, actStr)
}

// Test if OVS switch connects successfully
func TestMain(m *testing.M) {
	// Create a controller
	ctrler = NewController(&ofActor)

	// start listening
	go ctrler.Listen(":6733")

	// Connect to ovsdb and add the controller
	ovsDriver = ovsdbDriver.NewOvsDriver("ovsbr11")
	err := ovsDriver.AddController("127.0.0.1", 6733)
	if err != nil {
		log.Fatalf("Error adding controller to ovs")
	}

	//wait for 10sec and see if switch connects
	time.Sleep(10 * time.Second)
	if !ofActor.isSwitchConnected {
		log.Fatalf("ovsbr0 switch did not connect within 20sec")
		return
	}

	log.Infof("Switch connected. Creating tables..")

	// Create initial tables
	ofActor.inputTable = ofActor.Switch.DefaultTable()
	if ofActor.inputTable == nil {
		log.Fatalf("Failed to get input table")
		return
	}

	ofActor.nextTable, err = ofActor.Switch.NewTable(1)
	if err != nil {
		log.Fatalf("Error creating next table. Err: %v", err)
		return
	}

	log.Infof("Openflow tables created successfully")

	// run the test
	exitCode := m.Run()
	log.Infof("all test has run, exitcode: %d", exitCode)
	// delete the bridge
	err = ovsDriver.DeleteBridge("ovsbr11")
	if err != nil {
		log.Fatalf("Error deleting the bridge. Err: %v", err)
	}

	os.Exit(exitCode)
}

// test create/delete table
func TestTableCreateDelete(t *testing.T) {
	var tables [12]*Table

	log.Infof("Creating tables..")
	// create the tables
	for i := 2; i < 12; i++ {
		var err error
		tables[i], err = ofActor.Switch.NewTable(uint8(i))
		if err != nil {
			t.Errorf("Error creating table: %d", i)
		}
	}

	log.Infof("Deleting tables..")

	// delete the tables
	for i := 2; i < 12; i++ {
		err := tables[i].Delete()
		if err != nil {
			t.Errorf("Error deleting table: %d", i)
		}
	}
}

func TestCreateDeleteFlow(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set vlan and install it
	inPortFlow.SetVlan(1)
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// create an output
	output, err := ofActor.Switch.OutputPort(1)
	if err != nil {
		t.Errorf("Error creating an output port. Err: %v", err)
	}

	var vlan uint16 = 1
	// create mac flow
	macAddr, _ := net.ParseMAC("02:01:01:01:01:01")
	macFlow, err := ofActor.nextTable.NewFlow(FlowMatch{
		Priority: 100,
		VlanId:   &vlan,
		MacDa:    &macAddr,
	})
	if err != nil {
		t.Errorf("Error creating mac flow. Err: %v", err)
	}

	// Remove vlan and send out on a port
	macFlow.PopVlan()
	err = macFlow.Next(output)
	if err != nil {
		t.Errorf("Error installing the mac flow")
	}

	// Install ip flow
	ipAddr := net.ParseIP("10.10.10.10")
	ipFlow, err := ofActor.nextTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		IpDa:      &ipAddr,
	})
	if err != nil {
		t.Errorf("Error installing ip flow. Err: %v", err)
	}

	err = ipFlow.Next(output)
	if err != nil {
		t.Errorf("Error installing the ip flow")
	}

	// install tcp Flow
	tcpFlag := uint16(0x2)
	tcpFlow, err := ofActor.nextTable.NewFlow(FlowMatch{
		Priority:     100,
		Ethertype:    0x0800,
		IpProto:      6,
		TcpDstPort:   80,
		TcpFlags:     &tcpFlag,
		TcpFlagsMask: &tcpFlag,
	})
	if err != nil {
		t.Errorf("Error creating tcp flow. Err: %v", err)
	}

	log.Infof("Creating tcp flow: %+v", tcpFlow)
	err = tcpFlow.Next(output)
	if err != nil {
		t.Errorf("Error installing the tcp flow")
	}

	// newflow with flowid
	idFlow, err := ofActor.inputTable.NewFlowWithFlowID(FlowMatch{
		Priority:     100,
		Ethertype:    0x0800,
		IpProto:      6,
		TcpDstPort:   8080,
	}, 0x80)
	if err != nil {
		t.Errorf("Error creating flow with flowid")
	}
	log.Infof("Creating id flow: %+v", idFlow)
	if err := idFlow.Next(output); err != nil {
		t.Errorf("Error installing the id flow")
	}

	// verify it got installed
	flowList, err := ofctlFlowDump("ovsbr11")
	if err != nil {
		t.Errorf("Error getting flow entry")
	}

	// Match inport flow
	if !ofctlFlowMatch(flowList, 0, "priority=100,in_port=1",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// match ip flow
	if !ofctlFlowMatch(flowList, 1, "priority=100,ip,nw_dst=10.10.10.10",
		"output:1") {
		t.Errorf("IP flow not found in OVS.")
	}

	// match mac flow
	if !ofctlFlowMatch(flowList, 1, "priority=100,dl_vlan=1,dl_dst=02:01:01:01:01:01",
		"pop_vlan,output:1") {
		t.Errorf("Mac flow not found in OVS.")
		return
	}

	// match tcp flow
	if !ofctlFlowMatch(flowList, 1, "priority=100,tcp,tp_dst=80,tcp_flags=+syn",
		"output:1") {
		t.Errorf("IP flow not found in OVS.")
	}

	if !ofctlFlowMatchCookieID(flowList, 0x80) {
		t.Errorf("fix cookieID flow not found in OVS.")
	}

	// Delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Delete the flow
	err = macFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the mac flow. Err: %v", err)
	}

	// Delete the flow
	err = ipFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the ip flow. Err: %v", err)
	}

	// Delete the flow
	err = tcpFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the tcp flow. Err: %v", err)
	}

	if err = idFlow.Delete(); err != nil {
		t.Errorf("Error deleting the id flow. Err: %v", err)
	}

	// Make sure they are really gone
	flowList, err = ofctlFlowDump("ovsbr11")
	if err != nil {
		t.Errorf("Error getting flow entry")
	}
	if len(flowList) != 0 {
		t.Errorf("doesn't delete all flow: %s", flowList)
	}
}

// TestSetUnsetDscp verifies dscp set/unset action
func TestSetUnsetDscp(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		Ethertype: 0x0800,
		IpDscp:    46,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set vlan and dscp
	inPortFlow.SetVlan(1)
	inPortFlow.SetDscp(23)

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify dscp action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,ip,in_port=1,nw_tos=184",
		"set_field:23->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// unset dscp
	inPortFlow.UnsetDscp()

	// verify dscp action is gone
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,ip,in_port=1,nw_tos=184",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,in_port=1",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetMetadata verifies metadata match & set metedata
func TestMatchSetMetadata(t *testing.T) {
	metadata := uint64(0x1100)
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:     100,
		InputPort:    1,
		Metadata:     &metadata,
		MetadataMask: &metadata,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set Metadata
	inPortFlow.SetMetadata(uint64(0x8800), uint64(0x8800))

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,metadata=0x1100/0x1100,in_port=1",
		"write_metadata:0x8800/0x8800,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,metadata=0x1100/0x1100,in_port=1",
		"write_metadata:0x8800/0x8800,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetTunnelId verifies tunnelId match & set
func TestMatchSetTunnelId(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		TunnelId:  10,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set tunnelId
	inPortFlow.SetTunnelId(20)

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tun_id=0xa,in_port=1",
		"set_field:0x14->tun_id,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tun_id=0xa,in_port=1",
		"set_field:0x14->tun_id,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetIpFields verifies match & set for ip fields
func TestMatchSetIpFields(t *testing.T) {
	ipSa := net.ParseIP("10.1.1.1").Mask(net.CIDRMask(24, 32))
	ipDa := net.ParseIP("10.2.1.1").Mask(net.CIDRMask(24, 32))
	ipAddrMask := net.ParseIP("255.255.255.0")
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		Ethertype: 0x0800,
		IpSa:      &ipSa,
		IpSaMask:  &ipAddrMask,
		IpDa:      &ipDa,
		IpDaMask:  &ipAddrMask,
		IpProto:   IP_PROTO_TCP,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set ip src/dst
	inPortFlow.SetIPField(net.ParseIP("20.1.1.1"), "Src")
	inPortFlow.SetIPField(net.ParseIP("20.2.1.1"), "Dst")

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp,in_port=1,nw_src=10.1.1.0/24,nw_dst=10.2.1.0/24",
		"set_field:20.2.1.1->ip_dst,set_field:20.1.1.1->ip_src,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp,in_port=1,nw_src=10.1.1.0/24,nw_dst=10.2.1.0/24",
		"set_field:20.2.1.1->ip_dst,set_field:20.1.1.1->ip_src,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchIpv6Fields verifies match ipv6 fields
func TestMatchIpv6Fields(t *testing.T) {
	ipv6Sa, ipv6Net, _ := net.ParseCIDR("2016:0616::/100")
	ipv6Da, _, _ := net.ParseCIDR("2016:0617::/100")
	ipv6Mask := net.IP(ipv6Net.Mask)
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:   100,
		InputPort:  1,
		Ethertype:  0x86DD,
		Ipv6Sa:     &ipv6Sa,
		Ipv6SaMask: &ipv6Mask,
		Ipv6Da:     &ipv6Da,
		Ipv6DaMask: &ipv6Mask,
		IpProto:    IP_PROTO_TCP,
		IpDscp:     23,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set Metadata
	inPortFlow.SetDscp(46)

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp6,in_port=1,ipv6_src=2016:616::/100,ipv6_dst=2016:617::/100,nw_tos=92",
		"set_field:46->ip_dscp,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp6,in_port=1,ipv6_src=2016:616::/100,ipv6_dst=2016:617::/100,nw_tos=92",
		"set_field:46->ip_dscp,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetTcpFields verifies match & set for tcp fields
func TestMatchSetTcpFields(t *testing.T) {
	tcpFlag := uint16(0x12)
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:     100,
		InputPort:    1,
		Ethertype:    0x0800,
		IpProto:      IP_PROTO_TCP,
		TcpSrcPort:   8000,
		TcpDstPort:   9000,
		TcpFlags:     &tcpFlag,
		TcpFlagsMask: &tcpFlag,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set TCP src/dst
	inPortFlow.SetL4Field(4000, "TCPSrc")
	inPortFlow.SetL4Field(5000, "TCPDst")

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp,in_port=1,tp_src=8000,tp_dst=9000,tcp_flags=+syn+ack",
		"set_field:5000->tcp_dst,set_field:4000->tcp_src,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp,in_port=1,tp_src=8000,tp_dst=9000,tcp_flags=+syn+ack",
		"set_field:5000->tcp_dst,set_field:4000->tcp_src,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetUdpFields verifies match & set for udp fields
func TestMatchSetUdpFields(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:   100,
		InputPort:  1,
		Ethertype:  0x0800,
		IpProto:    IP_PROTO_UDP,
		UdpSrcPort: 8000,
		UdpDstPort: 9000,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set TCP src/dst
	inPortFlow.SetL4Field(4000, "UDPSrc")
	inPortFlow.SetL4Field(5000, "UDPDst")

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,udp,in_port=1,tp_src=8000,tp_dst=9000",
		"set_field:5000->udp_dst,set_field:4000->udp_src,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,udp,in_port=1,tp_src=8000,tp_dst=9000",
		"set_field:5000->udp_dst,set_field:4000->udp_src,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

func TestSetGroup(t *testing.T) {
	group, _ := ofActor.Switch.NewGroup(2, openflow13.OFPGT_SELECT)
	group.Install()

	flow, _ := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
	})
	flow.SetGroup(2)
	flow.Next(NewEmptyElem())

	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,ip", "group:2") {
		t.Errorf("failed to install flow action withh group")
	}
	group.Delete()
}

func TestCTWithZoneFiled(t *testing.T) {
	flow, _ := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
	})
	var tableID uint8 = 1
	ctAct, err := NewConntrackActionWithZoneField(false, false, &tableID, "nxm_nx_reg0", openflow13.NewNXRange(0, 15))
	if err != nil {
		t.Errorf("new ct action failed: %v", err)
	}
	err = flow.SetConntrack(ctAct)
	if err != nil {
		t.Errorf("SetConntrack failed: %v", err)
	}
	if err := flow.Next(NewEmptyElem()); err != nil {
		t.Errorf("SetConntrack failed: %v", err)
	}
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,ip", "ct(table=1,zone=NXM_NX_REG0[0..15])") {
		t.Errorf("failed to install ct flow with zone filed")
	}
	flow.Delete()
}

func TestCTNatAction(t *testing.T) {
	flow, _ := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
	})
	natAct, _ := NewNatAction().ToOfAction()
	var tableID uint8 = 1
	var zone uint16 = 65510
	ctAct := NewConntrackAction(true, false, &tableID, &zone, natAct)
	err := flow.SetConntrack(ctAct)
	if err != nil {
		t.Errorf("SetConntrack failed: %v", err)
	}
	if err := flow.Next(NewEmptyElem()); err != nil {
		t.Errorf("SetConntrack failed: %v", err)
	}

	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,ip", "ct(commit,table=1,zone=65510,nat)") {
		t.Errorf("faield to install ct flow with nat action")
	}

	flow.Delete()
}

func TestCTdNatAction(t *testing.T) {
	flow, _ := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
	})
	natAct, _ := NewDNatAction(NewIPRange(net.IPv4(10, 1, 1, 23)), NewPortRange(45, 50)).ToOfAction()
	var tableID uint8 = 1
	var zone uint16 = 65510
	ctAct := NewConntrackAction(true, false, &tableID, &zone, natAct)
	err := flow.SetConntrack(ctAct)
	if err != nil {
		t.Errorf("SetConntrack failed: %v", err)
	}
	if err := flow.Next(NewEmptyElem()); err != nil {
		t.Errorf("SetConntrack failed: %v", err)
	}

	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,ip", "ct(commit,table=1,zone=65510,nat(dst=10.1.1.23:45-50))") {
		t.Errorf("failed to install ct flow with nat action")
	}

	flow.Delete()
}

func TestLearnAction(t *testing.T) {
	flow, _ := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  90,
		Ethertype: 0x0800,
		IpProto:   0x06,
	})

	learnAct := NewLearnAction(3, 100, 0, 300, 0, 0, 0)
	learnAct.SetDeleteLearned()
	ethTypeField := LearnField{Name: "nxm_of_eth_type", Start: 0}
	ipProtoField := LearnField{Name: "nxm_of_ip_proto", Start: 0}

	tcpDstField := LearnField{Name: "nxm_of_tcp_dst", Start: 0}
	reg0 := LearnField{Name: "nxm_nx_reg0", Start: 10}

	learnAct.AddLearnedMatch(&ethTypeField, 16, nil, []byte{8, 0})
	learnAct.AddLearnedMatch(&ipProtoField, 8, nil, []byte{0, 6})
	learnAct.AddLearnedMatch(&tcpDstField, 16, &tcpDstField, nil)

	learnAct.AddLearnedLoadAction(&reg0, 1, nil, []byte{0, 1})

	flow.Learn(learnAct)
	flow.Next(NewEmptyElem())

	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=90,tcp", "learn(table=3,hard_timeout=300,priority=100,delete_learned,eth_type=0x800,nw_proto=6,NXM_OF_TCP_DST[],load:0x1->NXM_NX_REG0[10])") {
		t.Errorf("failed to install a flow with learn action")
	}

	flow.Delete()
}

func TestAlg(t *testing.T) {
	flow, _ := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:       100,
		Ethertype:      0x0800,
		IpProto:        0x06,
		TcpDstPort:     21,
		TcpDstPortMask: 65535,
	})
	var tableID uint8 = 1
	var zone uint16 = 65510
	ctAct := NewConntrackAction(true, false, &tableID, &zone)
	ctAct.SetAlg(21)
	err := flow.SetConntrack(ctAct)
	if err != nil {
		t.Errorf("SetConntrack failed: %v", err)
	}
	if err := flow.Next(NewEmptyElem()); err != nil {
		t.Errorf("SetConntrack failed: %v", err)
	}
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp,tp_dst=21", "ct(commit,table=1,zone=65510,alg=ftp") {
		t.Errorf("failed to install ct flow with nat action")
	}

	flow.Delete()
}

func TestSetTunndelDst(t *testing.T) {
	flow, _ := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x800,
	})
	_ = flow.SetTunnelDstIP(net.ParseIP("13.13.13.13"))
	if err := flow.Next(NewEmptyElem()); err != nil {
		t.Errorf("Set tunnel dst ip failed: %v", err)
	}
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,ip", "set_field:13.13.13.13->tun_dst") {
		t.Errorf("failed to install ct flow with set tunnel dst ip action")
	}
	flow.Delete()
}

func TestNewOFController(t *testing.T) {
	bridgeName := fmt.Sprintf("brtest-%d", rand.Intn(10))

	driver := ovsdbDriver.NewOvsDriver(bridgeName)
	defer driver.Delete()

	if err := driver.CreatePort(bridgeName, "internal", 0); err != nil {
		t.Fatalf("fail to create default internal port : %s", err)
	}

	_ = NewOFController(&ofActor, uint16(rand.Intn(1024)), driver.OVSClient(), bridgeName)

	//wait for 2sec
	time.Sleep(2 * time.Second)

	config, err := driver.GetOtherConfig()
	if err != nil {
		t.Fatalf("unable get other config: %s", err)
	}

	if config["datapath-id"] == "" {
		t.Fatalf("datapath id must be set before connect to switch")
	}

	if mac, err := driver.GetInternalPortMac(); err != nil || mac == "" {
		t.Fatalf("internal port mac must be set before connect to switch, err = %s", err)
	}
}
