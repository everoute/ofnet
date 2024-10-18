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

// This library implements a simple openflow 1.3 controller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/contiv/libOpenflow/common"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/util"
	ovsdb "github.com/contiv/libovsdb"

	log "github.com/sirupsen/logrus"
)

type PacketIn openflow13.PacketIn
type ConnectionMode int

const (
	ServerMode ConnectionMode = iota
	ClientMode
)

var (
	MaxRetry      = 100
	RetryInterval = 1 * time.Second
)

// Connection operation type
const (
	InitConnection = iota
	ReConnection
	CompleteConnection
)

// Note: Command to make ovs connect to controller:
// ovs-vsctl set-controller <bridge-name> tcp:<ip-addr>:<port>
// E.g.    sudo ovs-vsctl set-controller ovsbr0 tcp:127.0.0.1:6633

// To enable openflow1.3 support in OVS:
// ovs-vsctl set bridge <bridge-name> protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
// E.g. sudo ovs-vsctl set bridge ovsbr0 protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13

type AppInterface interface {
	// A Switch connected to the controller
	SwitchConnected(sw *OFSwitch)

	// Switch disconnected from the controller
	SwitchDisconnected(sw *OFSwitch)

	// Controller received a packet from the switch
	PacketRcvd(sw *OFSwitch, pkt *PacketIn)

	// Controller received a multi-part reply from the switch
	MultipartReply(sw *OFSwitch, rep *openflow13.MultipartReply)
}

type Option func(opt *options)

type Controller struct {
	app          AppInterface
	listener     *net.TCPListener
	wg           sync.WaitGroup
	connectMode  ConnectionMode
	connCh       chan int // Channel to control the UDS connection between controller and OFSwitch
	exitCh       chan struct{}
	controllerID uint16

	optionConfig *options
}

type options struct {
	disableCleanGroup bool
}

func DisableCleanGroup() Option {
	return func(opt *options) {
		opt.disableCleanGroup = true
	}
}

// Create a new controller
func NewController(app AppInterface, opts ...Option) *Controller {
	c := new(Controller)
	c.connectMode = ServerMode

	// for debug logs
	// log.SetLevel(log.DebugLevel)

	// Save the handler
	c.app = app

	c.optionConfig = &options{}
	for _, opt := range opts {
		opt(c.optionConfig)
	}
	return c
}

// Create a new controller
func NewControllerAsOFClient(app AppInterface, controllerID uint16, opts ...Option) *Controller {
	c := new(Controller)
	c.connectMode = ClientMode
	c.exitCh = make(chan struct{})
	c.app = app
	c.controllerID = controllerID

	c.optionConfig = &options{}
	for _, opt := range opts {
		opt(c.optionConfig)
	}

	return c
}

// Connect to Unix Domain Socket file
func (c *Controller) Connect(sock string) {
	if c.connCh == nil {
		c.connCh = make(chan int)
		c.exitCh = make(chan struct{})
		c.connectMode = ClientMode

		// Setup initial connection
		go func() {
			c.connCh <- InitConnection
		}()
	}

	var conn net.Conn
	var err error
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	for {
		select {
		case connCtrl := <-c.connCh:
			switch connCtrl {
			case InitConnection:
				fallthrough
			case ReConnection:
				log.Infof("Initialize connection or re-connect to %s.", sock)

				if conn != nil {
					// Try to close the existing connection
					_ = conn.Close()
				}

				// Retry to connect to the switch if hit error.
				conn, err = c.getConnection(sock, MaxRetry, RetryInterval)

				if err != nil {
					log.Fatalf("Failed to reconnect ovs-vswitchd after max retry, error: %v", err)
				}
				MaxRetry = 0
				c.wg.Add(1)
				log.Printf("Connected to socket %s", sock)

				go c.handleConnection(conn)

			case CompleteConnection:
				continue
			}
		case <-c.exitCh:
			log.Println("Controller is delete")
			return
		}
	}
}

func (c *Controller) getConnection(address string, maxRetry int, retryInterval time.Duration) (net.Conn, error) {
	var count int
	for {
		select {
		case <-time.After(retryInterval):
			conn, err := net.Dial("unix", address)
			if err == nil {
				return conn, nil
			}
			count++
			// Check if the re-connection times come to the max value, if true, return the error.
			// If it is required to re-connect until the Switch is connected, or the retry times it don't
			// come the max value, continually retry.
			if maxRetry > 0 && count == maxRetry {
				return nil, err
			}
			log.Errorf("Failed to connect to %s, retry after %s: %v.", address, retryInterval.String(), err)
		case <-c.exitCh:
			log.Info("Controller is deleted, stop re-connections")
			return nil, fmt.Errorf("controller is deleted, and connection is set as nil")
		}
	}
}

// Listen on a port
func (c *Controller) Listen(port string) {
	addr, _ := net.ResolveTCPAddr("tcp", port)

	var err error
	c.listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	defer c.listener.Close()

	log.Println("Listening for connections on", addr)
	for {
		conn, err := c.listener.AcceptTCP()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Fatal(err)
		}

		c.wg.Add(1)
		go c.handleConnection(conn)
	}

}

// Cleanup the controller
func (c *Controller) Delete() {
	if c.connectMode == ServerMode {
		c.listener.Close()
	} else if c.connectMode == ClientMode {
		// Send signal to stop connections to OF switch
		close(c.exitCh)
	}

	c.wg.Wait()
	c.app = nil
}

// Handle TCP connection from the switch
func (c *Controller) handleConnection(conn net.Conn) {
	var connFlag = ReConnection
	defer func() {
		c.connCh <- connFlag
	}()

	defer c.wg.Done()

	stream := util.NewMessageStream(conn, c)

	log.Println("New connection..")

	// Send ofp 1.3 Hello by default
	h, err := common.NewHello(4)
	if err != nil {
		return
	}
	stream.Outbound <- h

	for {
		select {
		// Send hello message with latest protocol version.
		case msg := <-stream.Inbound:
			switch m := msg.(type) {
			// A Hello message of the appropriate type
			// completes version negotiation. If version
			// types are incompatable, it is possible the
			// connection may be servered without error.
			case *common.Hello:
				if m.Version == openflow13.VERSION {
					log.Infoln("Received Openflow 1.3 Hello message")
					// Version negotiation is
					// considered complete. Create
					// new Switch and notifiy listening
					// applications.
					stream.Version = m.Version
					stream.Outbound <- openflow13.NewFeaturesRequest()
				} else {
					// Connection should be severed if controller
					// doesn't support switch version.
					log.Println("Received unsupported ofp version", m.Version)
					stream.Shutdown <- true
				}
			// After a vaild FeaturesReply has been received we
			// have all the information we need. Create a new
			// switch object and notify applications.
			case *openflow13.SwitchFeatures:
				log.Printf("Received ofp1.3 Switch feature response: %+v", *m)

				// Create a new switch and handover the stream
				var reConnChan chan int = nil
				if c.connectMode == ClientMode {
					reConnChan = c.connCh
				}
				s := NewSwitch(stream, m.DPID, c.app, reConnChan, c.controllerID, c.optionConfig.disableCleanGroup)
				if err := s.switchConnected(); err != nil {
					log.Errorf("Failed to initialize OpenFlow switch %s: %v", m.DPID, err)
					// Do not send event "ReConnection" in "switchDisconnected", because the event is sent in
					// defer logic in "handleConnection".
					s.switchDisconnected(false)
					return
				}
				connFlag = CompleteConnection
				// Let switch instance handle all future messages..
				return

			// An error message may indicate a version mismatch. We
			// disconnect if an error occurs this early.
			case *openflow13.ErrorMsg:
				log.Warnf("Received ofp1.3 error msg: %+v", *m)
				stream.Shutdown <- true
			}
		case err := <-stream.Error:
			// The connection has been shutdown.
			log.Infof("message stream error %v", err)
			return
		case <-time.After(time.Second * 3):
			// This shouldn't happen. If it does, both the controller
			// and switch are no longer communicating. The TCPConn is
			// still established though.
			log.Warnln("Connection timed out.")
			return
		}
	}
}

// Demux based on message version
func (c *Controller) Parse(b []byte) (message util.Message, err error) {
	switch b[0] {
	case openflow13.VERSION:
		message, err = openflow13.Parse(b)
	default:
		log.Errorf("Received unsupported openflow version: %d", b[0])
	}
	return
}

func (c *Controller) GetListenPort() int {
	return c.listener.Addr().(*net.TCPAddr).Port
}

func NewOFController(app AppInterface, controllerID uint16, conn *ovsdb.OvsdbClient, bridgeName string, opts ...Option) *Controller {
	if err := setDatapathID(conn, bridgeName); err != nil {
		log.Errorf("fail to set datapath id for bridge %s, errors = %s", bridgeName, err)
	}
	return NewControllerAsOFClient(app, controllerID, opts...)
}

func setDatapathID(conn *ovsdb.OvsdbClient, bridgeName string) error {
	if conn == nil {
		var err error
		conn, err = ovsdb.ConnectUnix(ovsdb.DEFAULT_SOCK)
		if err != nil {
			return fmt.Errorf("connect to ovsdb: %s", err)
		}
		defer conn.Disconnect()
	}

	h := sha256.New()
	h.Write([]byte(bridgeName))
	datapathID := h.Sum(nil)[:8]

	config, _ := ovsdb.NewOvsMap(map[string]string{"datapath-id": hex.EncodeToString(datapathID)})
	operation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Where:     []interface{}{[]interface{}{"name", "==", bridgeName}},
		Mutations: []interface{}{[]interface{}{"other_config", "insert", config}}, // never update the datapath id
	}
	_, err := ovsdbTransact(conn, "Open_vSwitch", operation)

	log.Infof("bridge %s datapath id has been set to %s", bridgeName, hex.EncodeToString(datapathID))
	return err
}

func ovsdbTransact(client *ovsdb.OvsdbClient, database string, operation ...ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	results, err := client.Transact(database, operation...)
	for item, result := range results {
		if result.Error != "" {
			return results, fmt.Errorf("operator %v: %s, details: %s", operation[item], result.Error, result.Details)
		}
	}
	return results, err
}
