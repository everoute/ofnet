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

// This file implements the forwarding graph API for the switch

import (
	"errors"
	"fmt"

	"github.com/contiv/libOpenflow/openflow13"
	cmap "github.com/orcaman/concurrent-map/v2"
	log "github.com/sirupsen/logrus"

	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/contiv/ofnet/ofctrl/dperror"
)

// Initialize the fgraph elements on the switch
func (self *OFSwitch) initFgraph() error {
	// Create the DBs
	self.tableDb = cmap.NewWithCustomShardingFunction[uint8, *Table](func(key uint8) uint32 { return uint32(key) })
	self.outputPorts = cmap.NewWithCustomShardingFunction[uint32, *Output](func(key uint32) uint32 { return key })
	self.groupDb = cmap.NewWithCustomShardingFunction[uint32, *Group](func(key uint32) uint32 { return key })

	// Create the table 0
	table := new(Table)
	table.Switch = self
	table.TableId = 0
	self.tableDb.Set(0, table)

	// Create drop action
	dropAction := new(Output)
	dropAction.outputType = "drop"
	dropAction.portNo = openflow13.P_ANY
	self.dropAction = dropAction

	// create send to controller action
	sendToCtrler := new(Output)
	sendToCtrler.outputType = "toController"
	sendToCtrler.portNo = openflow13.P_CONTROLLER
	self.sendToCtrler = sendToCtrler

	// Create normal lookup action.
	normalLookup := new(Output)
	normalLookup.outputType = "normal"
	normalLookup.portNo = openflow13.P_NORMAL
	self.normalLookup = normalLookup

	if self.disableCleanGroup {
		return nil
	}
	// Clear all existing flood lists
	groupMod := openflow13.NewGroupMod()
	groupMod.GroupId = openflow13.OFPG_ALL
	groupMod.Command = openflow13.OFPGC_DELETE
	groupMod.Type = openflow13.OFPGT_ALL
	self.Send(groupMod)

	return nil
}

// Create a new table. return an error if it already exists
func (self *OFSwitch) NewTable(tableId uint8) (*Table, error) {
	// Check the parameters
	if tableId == 0 {
		return nil, errors.New("Table 0 already exists")
	}

	// check if the table already exists
	if self.tableDb.Has(tableId) {
		return nil, errors.New("Table already exists")
	}

	// Create a new table
	table := new(Table)
	table.Switch = self
	table.TableId = tableId
	// Save it in the DB
	self.tableDb.Set(tableId, table)

	return table, nil
}

// Delete a table or specific flows.
// Return an error if there are fgraph nodes pointing at it
func (self *OFSwitch) DeleteSpecTableFlows(tableId uint8, priority *uint16, ofMatch []*openflow13.MatchField) error {
	// FIXME: to be implemented
	flowMod := openflow13.NewFlowMod()
	flowMod.TableId = tableId
	for _, field := range ofMatch {
		flowMod.Match.AddField(*field)
	}
	if priority == nil {
		self.tableDb.Remove(tableId)
		flowMod.Command = openflow13.FC_DELETE
		flowMod.OutPort = openflow13.P_ANY
		flowMod.OutGroup = openflow13.OFPG_ANY
	} else {
		flowMod.Priority = *priority
		flowMod.Command = openflow13.FC_DELETE_STRICT
	}

	log.Debugf("Sending DELETE table flowmod: %+v", flowMod)

	// Send the message
	if self == nil {
		return dperror.NewDpError(dperror.SwitchDisconnectedError.Code, dperror.SwitchDisconnectedError.Msg, fmt.Errorf("ofSwitch disconnected"))
	}
	self.Send(flowMod)

	return nil
}

// GetTable Returns a table
func (self *OFSwitch) GetTable(tableId uint8) *Table {
	t, _ := self.tableDb.Get(tableId)
	return t
}

// Return table 0 which is the starting table for all packets
func (self *OFSwitch) DefaultTable() *Table {
	t, _ := self.tableDb.Get(0)
	return t
}

// Return a output graph element for the port
func (self *OFSwitch) OutputPort(portNo uint32) (*Output, error) {
	if val, ok := self.outputPorts.Get(portNo); ok {
		return val, nil
	}

	// Create a new output element
	output := new(Output)
	output.outputType = "port"
	output.portNo = portNo

	// store all outputs in a DB
	self.outputPorts.Set(portNo, output)

	return output, nil
}

// Return a output graph element for the port reg
func (self *OFSwitch) OutputPortReg(regName string, offset uint16) (_ *Output, err error) {
	// Create a new output element
	output := new(Output)
	output.outputType = "reg"
	output.offset = offset<<6 + 15
	output.regField, err = openflow13.FindFieldHeaderByName(regName, true)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// Return the drop graph element
func (self *OFSwitch) DropAction() *Output {
	return self.dropAction
}

// SendToController Return send to controller graph element
func (self *OFSwitch) SendToController() *Output {
	return self.sendToCtrler
}

// NormalLookup Return normal lookup graph element
func (self *OFSwitch) NormalLookup() *Output {
	return self.normalLookup
}

// FIXME: Unique group id for the flood entries
var uniqueGroupId uint32 = 1

// Create a new flood list
func (self *OFSwitch) NewFlood() (*Flood, error) {
	flood := new(Flood)

	flood.Switch = self
	flood.GroupId = uniqueGroupId
	uniqueGroupId += 1

	// Install it in HW right away
	flood.install()

	return flood, nil
}

func (self *OFSwitch) DeleteFlowByRoundInfo(roundNum uint64) {
	cookie, cookieMask := cookie.RoundCookieWithMask(roundNum)
	self.DeleteFlowByCookie(cookie, cookieMask)
}

func (self *OFSwitch) DeleteFlowByCookie(cookieId, cookieMask uint64) {
	flowMod := openflow13.NewFlowMod()
	flowMod.Command = openflow13.FC_DELETE
	flowMod.Cookie = cookieId
	flowMod.CookieMask = cookieMask
	flowMod.OutPort = openflow13.P_ANY
	flowMod.OutGroup = openflow13.OFPG_ANY
	flowMod.TableId = openflow13.OFPTT_ALL

	self.Send(flowMod)
}

// Create a new group. return an error if it already exists
func (self *OFSwitch) NewGroup(groupId uint32, groupType uint8) (*Group, error) {
	// check if the group already exists
	if self.groupDb.Has(groupId) {
		return nil, errors.New("group already exists")
	}

	// Create a new group
	group := newGroup(groupId, groupType, self)
	// Save it in the DB
	self.groupDb.Set(groupId, group)

	return group, nil
}

func (self *OFSwitch) DeleteGroup(groupId uint32) {
	self.groupDb.Remove(groupId)
}

func (self *OFSwitch) GetGroup(groupId uint32) *Group {
	group, _ := self.groupDb.Get(groupId)
	return group
}
