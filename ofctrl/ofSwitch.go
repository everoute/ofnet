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
	"net"
	"time"

	"github.com/contiv/libOpenflow/common"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/util"

	cmap "github.com/orcaman/concurrent-map/v2"
	log "github.com/sirupsen/logrus"

	"github.com/contiv/ofnet/ofctrl/cookie"
)

type OFSwitch struct {
	stream *util.MessageStream
	dpid   net.HardwareAddr
	app    AppInterface
	// Following are fgraph state for the switch
	tableDb      cmap.ConcurrentMap[uint8, *Table]
	groupDb      cmap.ConcurrentMap[uint32, *Group]
	dropAction   *Output
	sendToCtrler *Output
	normalLookup *Output
	outputPorts  cmap.ConcurrentMap[uint32, *Output]

	CookieAllocator cookie.Allocator
	ready           bool
	retry           chan bool // Channel to notify controller reconnect switch
	ControllerID    uint16

	tlvMgr *tlvMapMgr

	disableCleanGroup bool
}

var switchDb cmap.ConcurrentMap[string, *OFSwitch]

func init() {
	switchDb = cmap.New[*OFSwitch]()
}

// Builds and populates a Switch struct then starts listening
// for OpenFlow messages on conn.
func NewSwitch(stream *util.MessageStream, dpid net.HardwareAddr, app AppInterface, retryChan chan bool, id uint16, disableCleanGroup bool) *OFSwitch {
	var s *OFSwitch

	if getSwitch(dpid) == nil {
		log.Infoln("Openflow Connection for new switch:", dpid)

		s = new(OFSwitch)
		s.app = app
		s.stream = stream
		s.dpid = dpid
		s.retry = retryChan
		s.ControllerID = id
		s.disableCleanGroup = disableCleanGroup

		// Initialize the fgraph elements
		s.initFgraph()

		// Save it
		switchDb.Set(dpid.String(), s)

		// Main receive loop for the switch
		go s.receive()

	} else {
		log.Infoln("Openflow Connection for switch:", dpid)

		s = getSwitch(dpid)
		s.stream = stream
		s.dpid = dpid
	}

	// send Switch connected callback
	s.tlvMgr = newTLVMapMgr()
	s.switchConnected()

	// Return the new switch
	return s
}

// Returns a pointer to the Switch mapped to dpid.
func getSwitch(dpid net.HardwareAddr) *OFSwitch {
	sw, _ := switchDb.Get(dpid.String())
	if sw == nil {
		return nil
	}
	return sw
}

// Returns the dpid of Switch s.
func (self *OFSwitch) DPID() net.HardwareAddr {
	return self.dpid
}

// Sends an OpenFlow message to this Switch.
func (self *OFSwitch) Send(req util.Message) {
	self.stream.Outbound <- req
}

func (self *OFSwitch) Disconnect() {
	self.stream.Shutdown <- true
	self.switchDisconnected()
}

// Handle switch connected event
func (self *OFSwitch) switchConnected() {

	// Send new feature request
	self.Send(openflow13.NewFeaturesRequest())

	// FIXME: This is too fragile. Create a periodic timer
	// Start the periodic echo request loop
	self.Send(openflow13.NewEchoRequest())
	self.requestTlvMap()
	self.app.SwitchConnected(self)
}

// Handle switch disconnected event
func (self *OFSwitch) switchDisconnected() {
	self.app.SwitchDisconnected(self)
	switchDb.Remove(self.DPID().String())
	if self.retry != nil {
		self.retry <- true
	}
}

// Receive loop for each Switch.
func (self *OFSwitch) receive() {
	for {
		select {
		case msg := <-self.stream.Inbound:
			// New message has been received from message
			// stream.
			self.handleMessages(self.dpid, msg)
		case err := <-self.stream.Error:
			log.Warnf("Received ERROR message from switch %v. Err: %v", self.dpid, err)

			// send Switch disconnected callback
			self.switchDisconnected()
			return
		}
	}
}

// Handle openflow messages from the switch
func (self *OFSwitch) handleMessages(dpid net.HardwareAddr, msg util.Message) {
	log.Debugf("Received message: %+v, on switch: %s", msg, dpid.String())

	switch t := msg.(type) {
	case *common.Header:
		switch t.Header().Type {
		case openflow13.Type_Hello:
			// Send Hello response
			h, err := common.NewHello(4)
			if err != nil {
				log.Errorf("Error creating hello message")
			}
			self.Send(h)

		case openflow13.Type_EchoRequest:
			// Send echo reply
			res := openflow13.NewEchoReply()
			self.Send(res)

		case openflow13.Type_EchoReply:

			// FIXME: This is too fragile. Create a periodic timer
			// Wait three seconds then send an echo_request message.
			go func() {
				<-time.After(time.Second * 3)

				// Send echo request
				res := openflow13.NewEchoRequest()
				self.Send(res)
			}()

		case openflow13.Type_FeaturesRequest:

		case openflow13.Type_GetConfigRequest:

		case openflow13.Type_BarrierRequest:

		case openflow13.Type_BarrierReply:

		}
	case *openflow13.ErrorMsg:
		log.Errorf("Received OpenFlow1.3 error: %s on msg %s, origin data: %s",
			GetErrorMessage(t.Type, t.Code, 0), GetErrorMessageType(t.Data), t.Data.String())
	case *openflow13.VendorHeader:
		switch t.ExperimenterType {
		case openflow13.Type_TlvTableReply:
			reply := t.VendorData.(*openflow13.TLVTableReply)
			status := TLVTableStatus(*reply)
			self.tlvMgr.TLVMapReplyRcvd(self, &status)
		}

	case *openflow13.SwitchFeatures:
		switch t.Header.Type {
		case openflow13.Type_FeaturesReply:
			swConfig := openflow13.NewSetConfig()
			swConfig.MissSendLen = 128
			self.Send(swConfig)
			self.Send(openflow13.NewSetControllerID(self.ControllerID))
		}

	case *openflow13.SwitchConfig:
		switch t.Header.Type {
		case openflow13.Type_GetConfigReply:

		case openflow13.Type_SetConfig:

		}
	case *openflow13.PacketIn:
		log.Debugf("Received packet(ofctrl): %+v", t)
		// send packet rcvd callback
		self.app.PacketRcvd(self, (*PacketIn)(t))

	case *openflow13.FlowRemoved:

	case *openflow13.PortStatus:
		// FIXME: This needs to propagated to the app.
	case *openflow13.PacketOut:

	case *openflow13.FlowMod:

	case *openflow13.PortMod:

	case *openflow13.MultipartRequest:

	case *openflow13.MultipartReply:
		log.Debugf("Received MultipartReply")
		// send packet rcvd callback
		self.app.MultipartReply(self, (*openflow13.MultipartReply)(t))

	}
}
