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

// This file implements the forwarding graph API for the table

import (
	"fmt"
	"github.com/contiv/libOpenflow/openflow13"

	"github.com/contiv/ofnet/ofctrl/dperror"
	log "github.com/sirupsen/logrus"
)

// Fgraph table element
type Table struct {
	Switch  *OFSwitch
	TableId uint8
}

// Fgraph element type for table
func (self *Table) Type() string {
	return "table"
}

// instruction set for table element
func (self *Table) GetFlowInstr() openflow13.Instruction {
	return openflow13.NewInstrGotoTable(self.TableId)
}

// FIXME: global unique flow cookie
var globalFlowID uint64 = 1

// Create a new flow on the table
func (self *Table) NewFlow(match FlowMatch) (*Flow, error) {
	if self.Switch == nil {
		return nil, dperror.NewDpError(dperror.SwitchDisconnectedError.Code, dperror.SwitchDisconnectedError.Msg, fmt.Errorf("ofSwitch disconnected"))
	}

	var flowID uint64
	if self.Switch.CookieAllocator != nil {
		var err error
		flowID, err = self.Switch.CookieAllocator.RequestCookie()
		if err != nil {
			return nil, err
		}
	} else {
		flowID = globalFlowID // FIXME: need a better id allocation
		globalFlowID += 1
	}

	return self.NewFlowWithFlowID(match, flowID)
}

func (self *Table) NewFlowWithFlowID(match FlowMatch, flowID uint64) (*Flow, error) {
	if self.Switch == nil {
		return nil, dperror.NewDpError(dperror.SwitchDisconnectedError.Code, dperror.SwitchDisconnectedError.Msg, fmt.Errorf("ofSwitch disconnected"))
	}
	flow := new(Flow)
	flow.Table = self
	flow.Match = match
	flow.isInstalled = false

	flow.FlowID = flowID
	flow.flowActions = make([]Action, 0)

	log.Debugf("Creating new flow for match: %+v", match)

	return flow, nil
}

// Delete the table
func (self *Table) Delete() error {
	// FIXME: Delete the table
	return nil
}
