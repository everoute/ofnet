/***
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

package ofnet

import (
	"errors"
	"net"
	"net/rpc"
	"reflect"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ofnet/ofctrl"
)

// This file has security policy rule implementation

const TCP_FLAG_ACK = 0x10
const TCP_FLAG_SYN = 0x2

// PolicyRule has info about single rule
type PolicyRule struct {
	Rule *OfnetPolicyRule // rule definition
	flow *ofctrl.Flow     // Flow associated with the flow
}

// PolicyAgent is an instance of a policy agent
type PolicyAgent struct {
	agent       *OfnetAgent             // Pointer back to ofnet agent that owns this
	ofSwitch    *ofctrl.OFSwitch        // openflow switch we are talking to
	dstGrpTable *ofctrl.Table           // dest group lookup table
	policyTable *ofctrl.Table           // Policy rule lookup table
	nextTable   *ofctrl.Table           // Next table to goto for accepted packets
	Rules       map[string]*PolicyRule  // rules database
	dstGrpFlow  map[string]*ofctrl.Flow // FLow entries for dst group lookup
	mutex       sync.RWMutex
}

// NewPolicyMgr Creates a new policy manager
func NewPolicyAgent(agent *OfnetAgent, rpcServ *rpc.Server) *PolicyAgent {
	policyAgent := new(PolicyAgent)

	// initialize
	policyAgent.agent = agent
	policyAgent.Rules = make(map[string]*PolicyRule)
	policyAgent.dstGrpFlow = make(map[string]*ofctrl.Flow)

	// Register for Master add/remove events
	rpcServ.Register(policyAgent)

	// done
	return policyAgent
}

// Handle switch connected notification
func (self *PolicyAgent) SwitchConnected(sw *ofctrl.OFSwitch) {
	// Keep a reference to the switch
	self.ofSwitch = sw

	log.Infof("Switch connected(policyAgent).")
}

// Handle switch disconnected notification
func (self *PolicyAgent) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	// FIXME: ??
}

// ruleIsSame check if two rules are identical
func ruleIsSame(r1, r2 *OfnetPolicyRule) bool {
	return reflect.DeepEqual(*r1, *r2)
}

func (self *PolicyAgent) AddEndpoint(endpoint *OfnetEndpoint) error {
	return nil
}

func (self *PolicyAgent) DelEndpoint(endpoint *OfnetEndpoint) error {
	return nil
}

func (self *PolicyAgent) AddIpv6Endpoint(endpoint *OfnetEndpoint) error {
	return nil
}

func (self *PolicyAgent) DelIpv6Endpoint(endpoint *OfnetEndpoint) error {
	return nil
}

// AddRule adds a security rule to policy table
func (self *PolicyAgent) AddRule(rule *OfnetPolicyRule, ret *bool) error {
	var ipDa *net.IP = nil
	var ipDaMask *net.IP = nil
	var ipSa *net.IP = nil
	var ipSaMask *net.IP = nil
	var flag, flagMask uint16
	var flagPtr, flagMaskPtr *uint16
	var err error

	// make sure switch is connected
	if !self.agent.IsSwitchConnected() {
		self.agent.WaitForSwitchConnection()
	}

	// check if we already have the rule
	self.mutex.RLock()
	if self.Rules[rule.RuleId] != nil {
		oldRule := self.Rules[rule.RuleId].Rule

		if ruleIsSame(oldRule, rule) {
			self.mutex.RUnlock()
			return nil
		} else {
			self.mutex.RUnlock()
			log.Errorf("Rule already exists. new rule: {%+v}, old rule: {%+v}", rule, oldRule)
			return errors.New("Rule already exists")
		}
	}
	self.mutex.RUnlock()

	log.Infof("Received AddRule: %+v", rule)

	// Parse dst ip
	if rule.DstIpAddr != "" {
		ipDa, ipDaMask, err = ParseIPAddrMaskString(rule.DstIpAddr)
		if err != nil {
			log.Errorf("Error parsing dst ip %s. Err: %v", rule.DstIpAddr, err)
			return err
		}
	}

	// parse src ip
	if rule.SrcIpAddr != "" {
		ipSa, ipSaMask, err = ParseIPAddrMaskString(rule.SrcIpAddr)
		if err != nil {
			log.Errorf("Error parsing src ip %s. Err: %v", rule.SrcIpAddr, err)
			return err
		}
	}

	// Setup TCP flags
	if rule.IpProtocol == 6 && rule.TcpFlags != "" {
		switch rule.TcpFlags {
		case "syn":
			flag = TCP_FLAG_SYN
			flagMask = TCP_FLAG_SYN
		case "syn,ack":
			flag = TCP_FLAG_ACK | TCP_FLAG_SYN
			flagMask = TCP_FLAG_ACK | TCP_FLAG_SYN
		case "ack":
			flag = TCP_FLAG_ACK
			flagMask = TCP_FLAG_ACK
		case "syn,!ack":
			flag = TCP_FLAG_SYN
			flagMask = TCP_FLAG_ACK | TCP_FLAG_SYN
		case "!syn,ack":
			flag = TCP_FLAG_ACK
			flagMask = TCP_FLAG_ACK | TCP_FLAG_SYN
		default:
			log.Errorf("Unknown TCP flags: %s, in rule: %+v", rule.TcpFlags, rule)
			return errors.New("Unknown TCP flag")
		}

		flagPtr = &flag
		flagMaskPtr = &flagMask
	}
	// Install the rule in policy table
	ruleFlow, err := self.policyTable.NewFlow(ofctrl.FlowMatch{
		Priority:     uint16(FLOW_POLICY_PRIORITY_OFFSET + rule.Priority),
		Ethertype:    0x0800,
		IpDa:         ipDa,
		IpDaMask:     ipDaMask,
		IpSa:         ipSa,
		IpSaMask:     ipSaMask,
		IpProto:      rule.IpProtocol,
		TcpSrcPort:   rule.SrcPort,
		TcpDstPort:   rule.DstPort,
		UdpSrcPort:   rule.SrcPort,
		UdpDstPort:   rule.DstPort,
		TcpFlags:     flagPtr,
		TcpFlagsMask: flagMaskPtr,
	})
	if err != nil {
		log.Errorf("Error adding flow for rule {%v}. Err: %v", rule, err)
		return err
	}

	// Point it to next table
	if rule.Action == "allow" {
		err = ruleFlow.Next(self.nextTable)
		if err != nil {
			log.Errorf("Error installing flow {%+v}. Err: %v", ruleFlow, err)
			return err
		}
	} else if rule.Action == "deny" {
		err = ruleFlow.Next(self.ofSwitch.DropAction())
		if err != nil {
			log.Errorf("Error installing flow {%+v}. Err: %v", ruleFlow, err)
			return err
		}
	} else {
		log.Errorf("Unknown action in rule {%+v}", rule)
		return errors.New("Unknown action in rule")
	}

	// save the rule
	pRule := PolicyRule{
		Rule: rule,
		flow: ruleFlow,
	}
	self.mutex.Lock()
	self.Rules[rule.RuleId] = &pRule
	self.mutex.Unlock()

	return nil
}

// DelRule deletes a security rule from policy table
func (self *PolicyAgent) DelRule(rule *OfnetPolicyRule, ret *bool) error {
	log.Infof("Received DelRule: %+v", rule)

	// Gte the rule
	self.mutex.Lock()
	defer self.mutex.Unlock()
	cache := self.Rules[rule.RuleId]
	if cache == nil {
		log.Errorf("Could not find rule: %+v", rule)
		return errors.New("rule not found")
	}

	// Delete the Flow
	err := cache.flow.Delete()
	if err != nil {
		log.Errorf("Error deleting flow: %+v. Err: %v", rule, err)
	}

	// Delete the rule from cache
	delete(self.Rules, rule.RuleId)

	return nil
}

// InitTables initializes policy table on the switch
func (self *PolicyAgent) InitTables(nextTblId uint8) error {
	sw := self.ofSwitch

	nextTbl := sw.GetTable(nextTblId)
	if nextTbl == nil {
		log.Fatalf("Error getting table id: %d", nextTblId)
	}

	self.nextTable = nextTbl

	// Create all tables
	self.dstGrpTable, _ = sw.NewTable(DST_GRP_TBL_ID)
	self.policyTable, _ = sw.NewTable(POLICY_TBL_ID)

	// Packets that miss dest group lookup still go to policy table
	validPktFlow, _ := self.dstGrpTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	validPktFlow.Next(self.policyTable)

	// Packets that didnt match any rule go to next table
	vlanMissFlow, _ := self.policyTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	vlanMissFlow.Next(nextTbl)

	return nil
}
