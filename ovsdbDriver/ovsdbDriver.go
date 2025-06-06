package ovsdbDriver

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/contiv/libovsdb"
	log "github.com/sirupsen/logrus"
)

// OVS driver state
type OvsDriver struct {
	// OVS client
	ovsClient *libovsdb.OvsdbClient

	// Name of the OVS bridge
	OvsBridgeName string

	// OVSDB cache
	ovsdbCache map[string]map[string]libovsdb.Row

	// read/write lock for accessing the cache
	lock sync.RWMutex
}

// Create a new OVS driver
func NewOvsDriver(bridgeName string) *OvsDriver {
	ovsDriver := new(OvsDriver)

	// connect to OVS
	ovs, err := libovsdb.ConnectUnix("/var/run/openvswitch/db.sock")
	if err != nil {
		log.Fatal("Failed to connect to ovsdb. Err: ", err)
	}

	// Setup state
	ovsDriver.ovsClient = ovs
	ovsDriver.OvsBridgeName = bridgeName
	ovsDriver.ovsdbCache = make(map[string]map[string]libovsdb.Row)

	// Register for notifications
	ovs.Register(ovsDriver)

	// Start monitor and Populate initial state into cache
	_ = ovs.MonitorAll("Open_vSwitch", "")

	// Create the default bridge instance
	if err = ovsDriver.CreateBridge(ovsDriver.OvsBridgeName); err != nil {
		log.Fatalf("Error creating the default bridge. Err: %v", err)
	}

	// Return the new OVS driver
	return ovsDriver
}

func NewOvsDriverForExistBridge(bridgeName string) *OvsDriver {
	ovsDriver := new(OvsDriver)

	// connect to OVS
	ovs, err := libovsdb.ConnectUnix("/var/run/openvswitch/db.sock")
	if err != nil {
		log.Fatal("Failed to connect to ovsdb. Err: ", err)
	}

	// Setup state
	ovsDriver.ovsClient = ovs
	ovsDriver.OvsBridgeName = bridgeName
	ovsDriver.ovsdbCache = make(map[string]map[string]libovsdb.Row)

	// Register for notifications
	ovs.Register(ovsDriver)

	selectAll := libovsdb.MonitorSelect{
		Initial: true,
		Insert:  true,
		Delete:  true,
		Modify:  true,
	}
	requests := map[string]libovsdb.MonitorRequest{
		"Port":         {Select: selectAll, Columns: []string{"name"}},
		"Bridge":       {Select: selectAll, Columns: []string{"name", "controller"}},
		"Open_vSwitch": {Select: selectAll, Columns: []string{"ovs_version"}},
	}

	// Start monitor and Populate initial state into cache
	_ = ovs.Monitor("Open_vSwitch", "", requests)

	if !ovsDriver.IsBridgePresent(bridgeName) {
		log.Fatalf("Ovs bridge: %v not exists, failed to create ovsdb dirver", bridgeName)
	}

	// Return the new OVS driver
	return ovsDriver
}

func (d *OvsDriver) OVSClient() *libovsdb.OvsdbClient {
	return d.ovsClient
}

// Delete : Cleanup the ovsdb driver. delete the bridge we created.
func (d *OvsDriver) Delete() error {
	if d.ovsClient != nil {
		d.DeleteBridge(d.OvsBridgeName)
		log.Infof("Deleting OVS bridge: %s", d.OvsBridgeName)
		(*d.ovsClient).Disconnect()
	}

	return nil
}

// Populate local cache of ovs state
func (self *OvsDriver) populateCache(updates libovsdb.TableUpdates) {
	// lock the cache for write
	self.lock.Lock()
	defer self.lock.Unlock()

	for table, tableUpdate := range updates.Updates {
		if _, ok := self.ovsdbCache[table]; !ok {
			self.ovsdbCache[table] = make(map[string]libovsdb.Row)

		}
		for uuid, row := range tableUpdate.Rows {
			empty := libovsdb.Row{}
			if !reflect.DeepEqual(row.New, empty) {
				self.ovsdbCache[table][uuid] = row.New
			} else {
				delete(self.ovsdbCache[table], uuid)
			}
		}
	}
}

// Dump the contents of the cache into stdout
func (self *OvsDriver) PrintCache() {
	// lock the cache for read
	self.lock.RLock()
	defer self.lock.RUnlock()

	fmt.Printf("OvsDB Cache: \n")

	// walk the local cache
	for tName, table := range self.ovsdbCache {
		fmt.Printf("Table: %s\n", tName)
		for uuid, row := range table {
			fmt.Printf("  Row: UUID: %s\n", uuid)
			for fieldName, value := range row.Fields {
				fmt.Printf("    Field: %s, Value: %+v\n", fieldName, value)
			}
		}
	}
}

// Get the UUID for root
func (self *OvsDriver) getRootUuid() libovsdb.UUID {
	// lock the cache for read
	self.lock.RLock()
	defer self.lock.RUnlock()

	// find the matching uuid
	for uuid := range self.ovsdbCache["Open_vSwitch"] {
		return libovsdb.UUID{GoUuid: uuid}
	}
	return libovsdb.UUID{}
}

// Wrapper for ovsDB transaction
func (self *OvsDriver) ovsdbTransact(ops []libovsdb.Operation) error {
	// Print out what we are sending
	log.Debugf("Transaction: %+v\n", ops)

	// Perform OVSDB transaction
	reply, _ := self.ovsClient.Transact("Open_vSwitch", ops...)

	if len(reply) < len(ops) {
		log.Errorf("Unexpected number of replies. Expected: %d, Recvd: %d", len(ops), len(reply))
		return errors.New("OVS transaction failed. Unexpected number of replies")
	}

	// Parse reply and look for errors
	for i, o := range reply {
		if o.Error != "" && i < len(ops) {
			return errors.New("OVS Transaction failed err " + o.Error + "Details: " + o.Details + " UUID: " + o.UUID.GoUuid)
		} else if o.Error != "" {
			return errors.New("OVS Transaction failed err " + o.Error + "Details: " + o.Details + " UUID: " + o.UUID.GoUuid)
		}
	}

	// Return success
	return nil
}

// **************** OVS driver API ********************
func (self *OvsDriver) CreateBridge(bridgeName string) error {
	namedUuidStr := "dummy"
	protocols := []string{"OpenFlow10", "OpenFlow11", "OpenFlow12", "OpenFlow13"}

	// If the bridge already exists, just return
	// FIXME: should we delete the old bridge and create new one?
	if self.IsBridgePresent(bridgeName) {
		return nil
	}

	// simple insert/delete operation
	brOp := libovsdb.Operation{}
	bridge := make(map[string]interface{})
	bridge["name"] = bridgeName
	bridge["protocols"], _ = libovsdb.NewOvsSet(protocols)
	bridge["fail_mode"] = "secure"
	brOp = libovsdb.Operation{
		Op:       "insert",
		Table:    "Bridge",
		Row:      bridge,
		UUIDName: namedUuidStr,
	}

	// Inserting/Deleting a Bridge row in Bridge table requires mutating
	// the open_vswitch table.
	brUuid := []libovsdb.UUID{{GoUuid: namedUuidStr}}
	mutateUuid := brUuid
	mutateSet, _ := libovsdb.NewOvsSet(mutateUuid)
	mutation := libovsdb.NewMutation("bridges", "insert", mutateSet)
	condition := libovsdb.NewCondition("_uuid", "==", self.getRootUuid())

	// simple mutate operation
	mutateOp := libovsdb.Operation{
		Op:        "mutate",
		Table:     "Open_vSwitch",
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}

	operations := []libovsdb.Operation{brOp, mutateOp}

	// operations := []libovsdb.Operation{brOp}
	return self.ovsdbTransact(operations)
}

// Delete a bridge from ovs
func (self *OvsDriver) DeleteBridge(bridgeName string) error {
	namedUuidStr := "dummy"
	brUuid := []libovsdb.UUID{{GoUuid: namedUuidStr}}

	// simple insert/delete operation
	brOp := libovsdb.Operation{}
	condition := libovsdb.NewCondition("name", "==", bridgeName)
	brOp = libovsdb.Operation{
		Op:    "delete",
		Table: "Bridge",
		Where: []interface{}{condition},
	}

	// lock the cache for read
	self.lock.RLock()
	// also fetch the br-uuid from cache
	for uuid, row := range self.ovsdbCache["Bridge"] {
		name := row.Fields["name"].(string)
		if name == bridgeName {
			brUuid = []libovsdb.UUID{{GoUuid: uuid}}
			break
		}
	}
	self.lock.RUnlock()

	// Inserting/Deleting a Bridge row in Bridge table requires mutating
	// the open_vswitch table.
	mutateUuid := brUuid
	mutateSet, _ := libovsdb.NewOvsSet(mutateUuid)
	mutation := libovsdb.NewMutation("bridges", "delete", mutateSet)
	condition = libovsdb.NewCondition("_uuid", "==", self.getRootUuid())

	// simple mutate operation
	mutateOp := libovsdb.Operation{
		Op:        "mutate",
		Table:     "Open_vSwitch",
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}

	operations := []libovsdb.Operation{brOp, mutateOp}
	return self.ovsdbTransact(operations)
}

func (self *OvsDriver) UpdateBridge(attrMap map[string][]string) error {
	var updateOperations []libovsdb.Operation
	condition := libovsdb.NewCondition("name", "==", self.OvsBridgeName)
	for attrName, list := range attrMap {
		updateOperation := libovsdb.Operation{
			Op:    "update",
			Table: "Bridge",
			Where: []interface{}{condition},
			Row: map[string]interface{}{
				attrName: makeOVSDBSetFromList(list),
			},
		}

		updateOperations = append(updateOperations, updateOperation)
	}

	return self.ovsdbTransact(updateOperations)
}

func (self *OvsDriver) GetExternalIds() (map[string]string, error) {
	selectOper := libovsdb.Operation{
		Op:      "select",
		Table:   "Bridge",
		Where:   []interface{}{[]interface{}{"name", "==", self.OvsBridgeName}},
		Columns: []string{"external_ids"},
	}

	opers := []libovsdb.Operation{selectOper}
	ovsBridgeExternalids, err := self.ovsClient.Transact("Open_vSwitch", opers...)
	if err != nil {
		return nil, fmt.Errorf("ovsdb select externalIds transaction failed: %v", opers)
	}
	if len(ovsBridgeExternalids[0].Rows) == 0 {
		return map[string]string{}, nil
	}
	externalIds := ovsBridgeExternalids[0].Rows[0]["external_ids"].([]interface{})

	return buildMapFromOVSDBMap(externalIds), nil
}

func (self *OvsDriver) GetRootExternalIds() (map[string]string, error) {
	selectOper := libovsdb.Operation{
		Op:      "select",
		Table:   "Open_vSwitch",
		Where:   []interface{}{[]interface{}{"ovs_version", "!=", ""}},
		Columns: []string{"external_ids"},
	}

	opers := []libovsdb.Operation{selectOper}
	ovsBridgeExternalids, err := self.ovsClient.Transact("Open_vSwitch", opers...)
	if err != nil {
		return nil, fmt.Errorf("ovsdb select externalIds transaction failed: %v, err: %s", opers, err)
	}
	if len(ovsBridgeExternalids[0].Rows) == 0 {
		return map[string]string{}, nil
	}
	externalIds := ovsBridgeExternalids[0].Rows[0]["external_ids"].([]interface{})

	return buildMapFromOVSDBMap(externalIds), nil
}

func (self *OvsDriver) SetRootExternalIds(externalIds map[string]string) error {
	oMap := buildOVSDBMapFromMap(externalIds)
	row := make(map[string]interface{})
	row["external_ids"] = oMap

	// simple insert operation
	updateOper := libovsdb.Operation{
		Op:    "update",
		Table: "Open_vSwitch",
		Where: []interface{}{[]interface{}{"ovs_version", "!=", ""}},
		Row:   row,
	}
	updateOpers := []libovsdb.Operation{updateOper}

	return self.ovsdbTransact(updateOpers)
}

func (self *OvsDriver) GetOtherConfig() (map[string]string, error) {
	selectOper := libovsdb.Operation{
		Op:      "select",
		Table:   "Bridge",
		Where:   []interface{}{[]interface{}{"name", "==", self.OvsBridgeName}},
		Columns: []string{"other_config"},
	}

	opers := []libovsdb.Operation{selectOper}
	ovsBridgeExternalids, err := self.ovsClient.Transact("Open_vSwitch", opers...)
	if err != nil {
		return nil, fmt.Errorf("ovsdb select other_config transaction failed: %v", opers)
	}
	if len(ovsBridgeExternalids[0].Rows) == 0 {
		return map[string]string{}, nil
	}
	externalIds := ovsBridgeExternalids[0].Rows[0]["other_config"].([]interface{})

	return buildMapFromOVSDBMap(externalIds), nil
}

func (self *OvsDriver) GetInternalPortMac() (string, error) {
	selectOper := libovsdb.Operation{
		Op:      "select",
		Table:   "Port",
		Where:   []interface{}{[]interface{}{"name", "==", self.OvsBridgeName}},
		Columns: []string{"mac"},
	}

	opers := []libovsdb.Operation{selectOper}
	ret, err := self.ovsClient.Transact("Open_vSwitch", opers...)
	if err != nil {
		return "", fmt.Errorf("ovsdb select internal port mac transaction failed: %v", opers)
	}

	if len(ret) == 0 || len(ret[0].Rows) == 0 {
		return "", nil
	}

	mac, ok := ret[0].Rows[0]["mac"].(string)
	if !ok {
		return "", nil
	}
	return mac, nil
}

func (self *OvsDriver) SetExternalIds(externalIds map[string]string) error {
	oMap := buildOVSDBMapFromMap(externalIds)
	row := make(map[string]interface{})
	row["external_ids"] = oMap

	// simple insert operation
	updateOper := libovsdb.Operation{
		Op:    "update",
		Table: "Bridge",
		Where: []interface{}{[]interface{}{"name", "==", self.OvsBridgeName}},
		Row:   row,
	}
	updateOpers := []libovsdb.Operation{updateOper}

	return self.ovsdbTransact(updateOpers)
}

func buildMapFromOVSDBMap(data []interface{}) map[string]string {
	if data[0] == "map" {
		ret := make(map[string]string)
		for _, pair := range data[1].([]interface{}) {
			ret[pair.([]interface{})[0].(string)] = pair.([]interface{})[1].(string)
		}
		return ret
	} else {
		return map[string]string{}
	}
}

func buildOVSDBMapFromMap(data map[string]string) []interface{} {
	list := []interface{}{}
	for k, v := range data {
		list = append(list, []string{k, v})
	}

	return []interface{}{
		"map",
		list,
	}
}

func (self *OvsDriver) UpdateInterface(ifaceName string, externalIDs map[string]string) error {
	if externalIDs == nil {
		externalIDs = make(map[string]string)
	}
	ovsExternalIDs, _ := libovsdb.NewOvsMap(externalIDs)

	portOperation := libovsdb.Operation{
		Op:    "update",
		Table: "Interface",
		Row: map[string]interface{}{
			"external_ids": ovsExternalIDs,
		},
		Where: []interface{}{[]interface{}{"name", "==", ifaceName}},
	}

	return self.ovsdbTransact([]libovsdb.Operation{portOperation})
}

// Create an internal port in OVS
func (self *OvsDriver) CreatePort(intfName, intfType string, vlanTag uint) error {
	portUuidStr := "portdummy"
	intfUuidStr := "ifacedummy"
	portUuid := []libovsdb.UUID{{GoUuid: portUuidStr}}
	intfUuid := []libovsdb.UUID{{GoUuid: intfUuidStr}}
	opStr := "insert"
	var err error = nil

	// insert/delete a row in Interface table
	intf := make(map[string]interface{})
	intf["name"] = intfName
	intf["type"] = intfType

	// Add an entry in Interface table
	intfOp := libovsdb.Operation{
		Op:       opStr,
		Table:    "Interface",
		Row:      intf,
		UUIDName: intfUuidStr,
	}

	// insert/delete a row in Port table
	port := make(map[string]interface{})
	port["name"] = intfName
	if vlanTag != 0 {
		port["vlan_mode"] = "access"
		port["tag"] = vlanTag
	} else {
		port["vlan_mode"] = "trunk"
	}

	port["interfaces"], err = libovsdb.NewOvsSet(intfUuid)
	if err != nil {
		return err
	}

	// Add an entry in Port table
	portOp := libovsdb.Operation{
		Op:       opStr,
		Table:    "Port",
		Row:      port,
		UUIDName: portUuidStr,
	}

	// mutate the Ports column of the row in the Bridge table
	mutateSet, _ := libovsdb.NewOvsSet(portUuid)
	mutation := libovsdb.NewMutation("ports", opStr, mutateSet)
	condition := libovsdb.NewCondition("name", "==", self.OvsBridgeName)
	mutateOp := libovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}

	// Perform OVS transaction
	operations := []libovsdb.Operation{intfOp, portOp, mutateOp}
	return self.ovsdbTransact(operations)
}

// Delete a port from OVS
func (self *OvsDriver) DeletePort(intfName string) error {
	portUuidStr := intfName
	portUuid := []libovsdb.UUID{{GoUuid: portUuidStr}}
	opStr := "delete"

	// insert/delete a row in Interface table
	condition := libovsdb.NewCondition("name", "==", intfName)
	intfOp := libovsdb.Operation{
		Op:    opStr,
		Table: "Interface",
		Where: []interface{}{condition},
	}

	// insert/delete a row in Port table
	condition = libovsdb.NewCondition("name", "==", intfName)
	portOp := libovsdb.Operation{
		Op:    opStr,
		Table: "Port",
		Where: []interface{}{condition},
	}

	// also fetch the port-uuid from cache
	// lock the cache for read
	self.lock.RLock()
	for uuid, row := range self.ovsdbCache["Port"] {
		name := row.Fields["name"].(string)
		if name == intfName {
			portUuid = []libovsdb.UUID{{GoUuid: uuid}}
			break
		}
	}
	self.lock.RUnlock()

	// mutate the Ports column of the row in the Bridge table
	mutateSet, _ := libovsdb.NewOvsSet(portUuid)
	mutation := libovsdb.NewMutation("ports", opStr, mutateSet)
	condition = libovsdb.NewCondition("name", "==", self.OvsBridgeName)
	mutateOp := libovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}

	// Perform OVS transaction
	operations := []libovsdb.Operation{intfOp, portOp, mutateOp}
	return self.ovsdbTransact(operations)
}

// Create a VTEP port on the OVS
func (self *OvsDriver) CreateVtep(intfName string, vtepRemoteIP string) error {
	portUuidStr := intfName
	intfUuidStr := fmt.Sprintf("Intf%s", intfName)
	portUuid := []libovsdb.UUID{{GoUuid: portUuidStr}}
	intfUuid := []libovsdb.UUID{{GoUuid: intfUuidStr}}
	opStr := "insert"
	intfType := "vxlan"
	var err error = nil

	// insert/delete a row in Interface table
	intf := make(map[string]interface{})
	intf["name"] = intfName
	intf["type"] = intfType

	// Special handling for VTEP ports
	intfOptions := make(map[string]interface{})
	intfOptions["remote_ip"] = vtepRemoteIP
	intfOptions["key"] = "flow" // Insert VNI per flow

	intf["options"], err = libovsdb.NewOvsMap(intfOptions)
	if err != nil {
		log.Errorf("error '%s' creating options from %v \n", err, intfOptions)
		return err
	}

	// Add an entry in Interface table
	intfOp := libovsdb.Operation{
		Op:       opStr,
		Table:    "Interface",
		Row:      intf,
		UUIDName: intfUuidStr,
	}

	// insert/delete a row in Port table
	port := make(map[string]interface{})
	port["name"] = intfName
	port["vlan_mode"] = "trunk"

	port["interfaces"], err = libovsdb.NewOvsSet(intfUuid)
	if err != nil {
		return err
	}

	// Add an entry in Port table
	portOp := libovsdb.Operation{
		Op:       opStr,
		Table:    "Port",
		Row:      port,
		UUIDName: portUuidStr,
	}

	// mutate the Ports column of the row in the Bridge table
	mutateSet, _ := libovsdb.NewOvsSet(portUuid)
	mutation := libovsdb.NewMutation("ports", opStr, mutateSet)
	condition := libovsdb.NewCondition("name", "==", self.OvsBridgeName)
	mutateOp := libovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}

	// Perform OVS transaction
	operations := []libovsdb.Operation{intfOp, portOp, mutateOp}
	return self.ovsdbTransact(operations)
}

// Delete a VTEP port
func (self *OvsDriver) DeleteVtep(intfName string) error {
	return self.DeletePort(intfName)
}

// Add controller configuration to OVS
func (self *OvsDriver) AddController(ipAddr string, portNo uint16) error {
	// Format target string
	target := fmt.Sprintf("tcp:%s:%d", ipAddr, portNo)
	ctrlerUuidStr := fmt.Sprintf("local")
	ctrlerUuid := []libovsdb.UUID{{GoUuid: ctrlerUuidStr}}

	// If controller already exists, nothing to do
	if self.IsControllerPresent(ipAddr, portNo) {
		return nil
	}

	// insert a row in Controller table
	controller := make(map[string]interface{})
	controller["target"] = target

	// Add an entry in Controller table
	ctrlerOp := libovsdb.Operation{
		Op:       "insert",
		Table:    "Controller",
		Row:      controller,
		UUIDName: ctrlerUuidStr,
	}

	// mutate the Controller column of the row in the Bridge table
	mutateSet, _ := libovsdb.NewOvsSet(ctrlerUuid)
	mutation := libovsdb.NewMutation("controller", "insert", mutateSet)
	condition := libovsdb.NewCondition("name", "==", self.OvsBridgeName)
	mutateOp := libovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}

	// Perform OVS transaction
	operations := []libovsdb.Operation{ctrlerOp, mutateOp}
	return self.ovsdbTransact(operations)
}

func (self *OvsDriver) RemoveController() error {
	// clean controller configured in ovsdb
	var controllerOperations, mutateOperations []libovsdb.Operation
	var ctrlUUIDList []libovsdb.UUID
	self.lock.Lock()
	for _, row := range self.ovsdbCache["Bridge"] {
		if row.Fields["name"] == self.OvsBridgeName {
			ctrlUUIDList = listUUID(row.Fields["controller"])
			break
		}
	}
	self.lock.Unlock()

	for _, ctrlUUID := range ctrlUUIDList {
		condition := libovsdb.NewCondition("_uuid", "==", ctrlUUID)
		ctrlOperation := libovsdb.Operation{
			Op:    "delete",
			Table: "Controller",
			Where: []interface{}{condition},
		}
		controllerOperations = append(controllerOperations, ctrlOperation)

		mutateSet, _ := libovsdb.NewOvsSet([]libovsdb.UUID{ctrlUUID})
		mutation := libovsdb.NewMutation("controller", "delete", mutateSet)
		condition = libovsdb.NewCondition("name", "==", self.OvsBridgeName)
		mutateOperation := libovsdb.Operation{
			Op:        "mutate",
			Table:     "Bridge",
			Mutations: []interface{}{mutation},
			Where:     []interface{}{condition},
		}
		mutateOperations = append(mutateOperations, mutateOperation)
	}

	// Perform OVS transaction
	var operations []libovsdb.Operation
	operations = append(operations, controllerOperations...)
	operations = append(operations, mutateOperations...)

	return self.ovsdbTransact(operations)
}

// Check the local cache and see if the portname is taken already
// HACK alert: This is used to pick next port number instead of managing
// port number space actively across agent restarts
func (self *OvsDriver) IsPortNamePresent(intfName string) bool {
	// lock the cache for read
	self.lock.RLock()
	defer self.lock.RUnlock()

	// walk the local cache
	for tName, table := range self.ovsdbCache {
		if tName == "Port" {
			for _, row := range table {
				for fieldName, value := range row.Fields {
					if fieldName == "name" {
						if value == intfName {
							// Interface name exists.
							return true
						}
					}
				}
			}
		}
	}

	// We could not find the interface name
	return false
}

// Check if the bridge entry already exists
func (self *OvsDriver) IsBridgePresent(bridgeName string) bool {
	// lock the cache for read
	self.lock.RLock()
	defer self.lock.RUnlock()

	// walk the bridge table in cache
	for tName, table := range self.ovsdbCache {
		if tName == "Bridge" {
			for _, row := range table {
				for fieldName, value := range row.Fields {
					if fieldName == "name" {
						if value == bridgeName {
							// Interface name exists.
							return true
						}
					}
				}
			}
		}
	}

	// We could not find the interface name
	return false
}

// Check if Controller already exists
func (self *OvsDriver) IsControllerPresent(ipAddr string, portNo uint16) bool {
	// lock the cache for read
	self.lock.RLock()
	defer self.lock.RUnlock()

	// walk the locak cache
	target := fmt.Sprintf("tcp:%s:%d", ipAddr, portNo)
	for tName, table := range self.ovsdbCache {
		if tName == "Controller" {
			for _, row := range table {
				for fieldName, value := range row.Fields {
					if fieldName == "target" {
						if value == target {
							// Controller exists.
							return true
						}
					}
				}
			}
		}
	}

	// We could not find the interface name
	return false
}

// Check if VTEP already exists
func (self *OvsDriver) IsVtepPresent(remoteIP string) (bool, string) {
	// lock the cache for read
	self.lock.RLock()
	defer self.lock.RUnlock()

	// walk the local cache
	for tName, table := range self.ovsdbCache {
		if tName == "Interface" {
			for _, row := range table {
				options := row.Fields["options"]
				switch optMap := options.(type) {
				case libovsdb.OvsMap:
					if optMap.GoMap["remote_ip"] == remoteIP {
						value := row.Fields["name"]
						switch t := value.(type) {
						case string:
							return true, t
						default:
							// return false, ""
						}
					}
				default:
					// return false, ""
				}
			}
		}
	}

	// We could not find the interface name
	return false, ""
}

// Return OFP port number for an interface
func (self *OvsDriver) GetOfpPortNo(intfName string) (uint32, error) {
	retryNo := 0
	condition := libovsdb.NewCondition("name", "==", intfName)
	selectOp := libovsdb.Operation{
		Op:    "select",
		Table: "Interface",
		Where: []interface{}{condition},
	}

	for {
		row, err := self.ovsClient.Transact("Open_vSwitch", selectOp)

		if err == nil && len(row) > 0 && len(row[0].Rows) > 0 {
			value := row[0].Rows[0]["ofport"]
			if reflect.TypeOf(value).Kind() == reflect.Float64 {
				//retry few more time. Due to asynchronous call between
				//port creation and populating ovsdb entry for the interface
				//may not be populated instantly.
				var ofpPort uint32 = uint32(reflect.ValueOf(value).Float())
				return ofpPort, nil
			}
		}
		time.Sleep(200 * time.Millisecond)

		if retryNo == 5 {
			return 0, errors.New("ofPort not found")
		}
		retryNo++
	}
}

func listUUID(uuidList interface{}) []libovsdb.UUID {
	var idList []libovsdb.UUID

	switch uuidList.(type) {
	case libovsdb.UUID:
		return []libovsdb.UUID{uuidList.(libovsdb.UUID)}
	case libovsdb.OvsSet:
		uuidSet := uuidList.(libovsdb.OvsSet).GoSet
		for item := range uuidSet {
			idList = append(idList, listUUID(uuidSet[item])...)
		}
	}

	return idList
}

func makeOVSDBSetFromList(list []string) []interface{} {
	return []interface{}{"set", list}
}

// ************************ Notification handler for OVS DB changes ****************
func (self *OvsDriver) Update(context interface{}, tableUpdates libovsdb.TableUpdates) {
	// fmt.Printf("Received OVS update: %+v\n\n", tableUpdates)
	self.populateCache(tableUpdates)
}
func (self *OvsDriver) Disconnected(ovsClient *libovsdb.OvsdbClient) {
	log.Errorf("OVS BD client disconnected")
}
func (self *OvsDriver) Locked([]interface{}) {
}
func (self *OvsDriver) Stolen([]interface{}) {
}
func (self *OvsDriver) Echo([]interface{}) {
}
