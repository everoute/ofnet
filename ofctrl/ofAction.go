package ofctrl

import (
	"errors"
	"net"

	"github.com/contiv/libOpenflow/openflow13"
)

const (
	ActTypePushVlan       = "pushVlan"
	ActTypeSetVlan        = "setVlan"
	ActTypePopVlan        = "popVlan"
	ActTypeSetDstMac      = "setMacDa"
	ActTypeSetSrcMac      = "setMacSa"
	ActTypeSetTunnelID    = "setTunnelId"
	ActTypeSetTunnelDstIP = "setTunnelDstIP"
	ActTypeMetatdata      = "setMetadata"
	ActTypeSetSrcIP       = "setIP"
	ActTypeSetDstIP       = "setIPDa"
	ActTypeSetDSCP        = "setDscp"
	ActTypeSetTCPsPort    = "setTCPSrc"
	ActTypeSetTCPdPort    = "setTCPDst"
	ActTypeSetUDPsPort    = "setUDPSrc"
	ActTypeSetUDPdPort    = "setUDPDst"
	ActTypeNXLoad         = "loadAction"
	ActTypeNXMove         = "moveAction"
	ActTypeCT             = "ct"
	ActTypeCTClear        = "ctClear"
	ActTypeCTNAT          = "nat"
	ActTypeNXResubmit     = "resubmitAction"
	ActTypeGroup          = "groupAction"
	ActTypeNXLearn        = "learnAction"
	ActTypeController     = "controller"
	ActTypeOutput         = "outputAction"
	ActTypeDecNwTtl       = "DecNwTtl"
)

type Action interface {
	GetActionType() string
	ToOfAction() (openflow13.Action, error)
}

type NXController struct {
	id     uint16
	reason uint8
}

func NewControllerAction(controllerID uint16, reason uint8) *NXController {
	return &NXController{
		id:     controllerID,
		reason: reason,
	}
}

func (a *NXController) ToOfAction() (openflow13.Action, error) {
	return openflow13.NewNXActionController(a.id), nil
}

func (a *NXController) GetActionType() string {
	return ActTypeController
}

type OutputAction struct {
	outputPort uint32
}

func NewOutputAction(outputPort uint32) *OutputAction {
	outputAction := new(OutputAction)
	outputAction.outputPort = outputPort

	return outputAction
}

func (a *OutputAction) ToOfAction() (openflow13.Action, error) {
	return openflow13.NewActionOutput(a.outputPort), nil
}

func (a *OutputAction) GetActionType() string {
	return ActTypeOutput
}

type CTClearAction struct{}

func NewCTClearAction() *CTClearAction {
	return &CTClearAction{}
}

func (a *CTClearAction) ToOfAction() (openflow13.Action, error) {
	return openflow13.NewNXActionCTClear(), nil
}

func (a *CTClearAction) GetActionType() string {
	return ActTypeCTClear
}

type ConnTrackAction struct {
	Commit    bool
	Force     bool
	Table     *uint8
	Zone      *uint16
	ZoneField *openflow13.MatchField
	ZoneRange *openflow13.NXRange
	Alg       *uint16
	Actions   []openflow13.Action
}

func NewConntrackAction(commit bool, force bool, table *uint8, zone *uint16, actions ...openflow13.Action) *ConnTrackAction {
	return &ConnTrackAction{
		Commit:  commit,
		Force:   force,
		Table:   table,
		Zone:    zone,
		Actions: actions,
	}
}

func NewConntrackActionWithZoneField(commit bool, force bool, table *uint8, zoneFieldName string, zoneRange *openflow13.NXRange,
	actions ...openflow13.Action) (*ConnTrackAction, error) {
	zoneFiled, err := openflow13.FindFieldHeaderByName(zoneFieldName, true)
	if err != nil {
		return nil, err
	}
	return &ConnTrackAction{
		Commit:    commit,
		Force:     force,
		Table:     table,
		ZoneField: zoneFiled,
		ZoneRange: zoneRange,
		Actions:   actions,
	}, nil
}

func (a *ConnTrackAction) SetAlg(alg uint16) {
	a.Alg = &alg
}

func (a *ConnTrackAction) ToOfAction() (openflow13.Action, error) {
	ctAction := openflow13.NewNXActionConnTrack()

	if a.Commit {
		ctAction.Commit()
	}
	if a.Force {
		ctAction.Force()
	}
	if a.Table != nil {
		ctAction.Table(*a.Table)
	}
	if a.Zone != nil {
		ctAction.ZoneImm(*a.Zone)
	}
	if a.ZoneField != nil && a.ZoneRange != nil {
		ctAction.ZoneRange(a.ZoneField, a.ZoneRange)
	}
	if a.Alg != nil {
		ctAction.Alg = *a.Alg
	}
	if a.Actions != nil {
		ctAction = ctAction.AddAction(a.Actions...)
	}

	return ctAction, nil
}

func (a *ConnTrackAction) GetActionType() string {
	return ActTypeCT
}

type PushVlanAction struct {
	etherType uint16
}

func NewPushVlanAction(etherType uint16) *PushVlanAction {
	return &PushVlanAction{etherType}
}

func (a *PushVlanAction) ToOfAction() (openflow13.Action, error) {
	return openflow13.NewActionPushVlan(a.etherType), nil
}

func (a *PushVlanAction) GetActionType() string {
	return ActTypePushVlan
}

type SetVlanAction struct {
	vlanID uint16
}

func NewSetVlanAction(vlanID uint16) *SetVlanAction {
	return &SetVlanAction{vlanID}
}

func (a *SetVlanAction) ToOfAction() (openflow13.Action, error) {
	vlanField := openflow13.NewVlanIdField(a.vlanID, nil)
	return openflow13.NewActionSetField(*vlanField), nil
}

func (a *SetVlanAction) GetActionType() string {
	return ActTypeSetVlan
}

type PopVlanAction struct{}

func NewPopVlanAction() *PopVlanAction {
	return &PopVlanAction{}
}

func (a *PopVlanAction) ToOfAction() (openflow13.Action, error) {
	return openflow13.NewActionPopVlan(), nil
}

func (a *PopVlanAction) GetActionType() string {
	return ActTypePopVlan
}

type SetDstMac struct {
	macAddr net.HardwareAddr
}

func NewSetDstMac(macAddr net.HardwareAddr) *SetDstMac {
	return &SetDstMac{macAddr}
}

func (a *SetDstMac) ToOfAction() (openflow13.Action, error) {
	macDaField := openflow13.NewEthDstField(a.macAddr, nil)
	return openflow13.NewActionSetField(*macDaField), nil
}

func (a *SetDstMac) GetActionType() string {
	return ActTypeSetDstMac
}

type SetSrcMac struct {
	macAddr net.HardwareAddr
}

func NewSetSrcMac(macAddr net.HardwareAddr) *SetSrcMac {
	return &SetSrcMac{macAddr}
}

func (a *SetSrcMac) ToOfAction() (openflow13.Action, error) {
	macSaField := openflow13.NewEthSrcField(a.macAddr, nil)
	return openflow13.NewActionSetField(*macSaField), nil
}

func (a *SetSrcMac) GetActionType() string {
	return ActTypeSetSrcMac
}

type SetDstIP struct {
	ipAddr net.IP
}

func NewSetDstIP(ipAddr net.IP) *SetDstIP {
	return &SetDstIP{ipAddr}
}

func (a *SetDstIP) ToOfAction() (openflow13.Action, error) {
	ipDaField := openflow13.NewIpv4DstField(a.ipAddr, nil)
	return openflow13.NewActionSetField(*ipDaField), nil
}

func (a *SetDstIP) GetActionType() string {
	return ActTypeSetDstIP
}

type SetSrcIP struct {
	ipAddr net.IP
}

func NewSetSrcIP(ipAddr net.IP) *SetSrcIP {
	return &SetSrcIP{ipAddr}
}

func (a *SetSrcIP) ToOfAction() (openflow13.Action, error) {
	ipSaField := openflow13.NewIpv4SrcField(a.ipAddr, nil)
	return openflow13.NewActionSetField(*ipSaField), nil
}

func (a *SetSrcIP) GetActionType() string {
	return ActTypeSetSrcIP
}

type SetTunnelID struct {
	tunnelID uint64
}

func NewSetTunnelID(tunnelID uint64) *SetTunnelID {
	return &SetTunnelID{tunnelID}
}

func (a *SetTunnelID) ToOfAction() (openflow13.Action, error) {
	tunnelIdField := openflow13.NewTunnelIdField(a.tunnelID)
	return openflow13.NewActionSetField(*tunnelIdField), nil
}

func (a *SetTunnelID) GetActionType() string {
	return ActTypeSetTunnelID
}

type SetTunnelDstIP struct {
	tunnelDstIP net.IP
}

func NewSetTunnelDstIP(dstIP net.IP) *SetTunnelDstIP {
	return &SetTunnelDstIP{
		tunnelDstIP: dstIP,
	}
}

func (a *SetTunnelDstIP) ToOfAction() (openflow13.Action, error) {
	tunnelDstIPv4 := openflow13.NewTunnelIpv4DstField(a.tunnelDstIP, nil)
	return openflow13.NewActionSetField(*tunnelDstIPv4), nil
}

func (a *SetTunnelDstIP) GetActionType() string {
	return ActTypeSetTunnelDstIP
}

type SetMetadata struct {
	metadata     uint64
	metadataMask uint64
}

func NewSetMetadata(metadata, metadataMask uint64) *SetMetadata {
	return &SetMetadata{metadata, metadataMask}
}

func (a *SetMetadata) ToOfAction() (openflow13.Action, error) {
	return nil, errors.New("not support for action: setMetadata")
}

func (a *SetMetadata) GetActionType() string {
	return ActTypeMetatdata
}

type SetDscp struct {
	dscp uint8
}

func NewSetDscp(dscp uint8) *SetDscp {
	return &SetDscp{dscp}
}

func (a *SetDscp) ToOfAction() (openflow13.Action, error) {
	ipDscpField := openflow13.NewIpDscpField(a.dscp)
	return openflow13.NewActionSetField(*ipDscpField), nil
}

func (a *SetDscp) GetActionType() string {
	return ActTypeSetDSCP
}

type SetTCPSrc struct {
	l4Port uint16
}

func NewSetTCPSrc(l4Port uint16) *SetTCPSrc {
	return &SetTCPSrc{l4Port}
}

func (a *SetTCPSrc) ToOfAction() (openflow13.Action, error) {
	tcpSrcField := openflow13.NewTcpSrcField(a.l4Port)
	return openflow13.NewActionSetField(*tcpSrcField), nil
}

func (a *SetTCPSrc) GetActionType() string {
	return ActTypeSetTCPsPort
}

type SetTCPDst struct {
	l4Port uint16
}

func NewSetTCPDst(l4Port uint16) *SetTCPDst {
	return &SetTCPDst{l4Port}
}

func (a *SetTCPDst) ToOfAction() (openflow13.Action, error) {
	tcpDstField := openflow13.NewTcpDstField(a.l4Port)
	return openflow13.NewActionSetField(*tcpDstField), nil
}

func (a *SetTCPDst) GetActionType() string {
	return ActTypeSetTCPdPort
}

type SetUDPSrc struct {
	l4Port uint16
}

func NewSetUDPSrc(l4Port uint16) *SetUDPSrc {
	return &SetUDPSrc{l4Port}
}

func (a *SetUDPSrc) ToOfAction() (openflow13.Action, error) {
	udpSrcField := openflow13.NewUdpSrcField(a.l4Port)
	return openflow13.NewActionSetField(*udpSrcField), nil
}

func (a *SetUDPSrc) GetActionType() string {
	return ActTypeSetUDPsPort
}

type SetUDPDst struct {
	l4Port uint16
}

func NewSetUDPDst(l4Port uint16) *SetUDPDst {
	return &SetUDPDst{l4Port}
}

func (a *SetUDPDst) ToOfAction() (openflow13.Action, error) {
	udpDstField := openflow13.NewUdpDstField(a.l4Port)
	return openflow13.NewActionSetField(*udpDstField), nil
}

func (a *SetUDPDst) GetActionType() string {
	return ActTypeSetUDPdPort
}

type ResubmitAction struct {
	tableId uint8
	inPort  uint16
	prepend bool
}

func NewResubmitAction(inPort *uint16, table *uint8) *ResubmitAction {
	resubmit := new(ResubmitAction)
	if inPort == nil {
		resubmit.inPort = openflow13.OFPP_IN_PORT
	} else {
		resubmit.inPort = *inPort
	}

	if table == nil {
		resubmit.tableId = openflow13.OFPTT_ALL
	} else {
		resubmit.tableId = *table
	}

	return resubmit
}

func (a *ResubmitAction) ToOfAction() (openflow13.Action, error) {
	return openflow13.NewNXActionResubmitTableAction(a.inPort, a.tableId), nil
}

func (a *ResubmitAction) GetActionType() string {
	return ActTypeNXResubmit
}

type LearnAction struct {
	idleTimeout    uint16
	hardTimeout    uint16
	priority       uint16
	cookie         uint64
	flags          uint16
	tableID        uint8
	pad            uint8
	finIdleTimeout uint16
	finHardTimeout uint16
	specs          []*openflow13.NXLearnSpec
	pad2           []byte
}

type LearnField struct {
	Name  string
	Start uint16
}

func NewLearnAction(tableId uint8, priority, idleTimeout, hardTimeout, finIdleTimeout, finHardTimeout uint16, cookieId uint64) *LearnAction {
	return &LearnAction{
		idleTimeout:    idleTimeout,
		hardTimeout:    hardTimeout,
		priority:       priority,
		cookie:         cookieId,
		tableID:        tableId,
		finHardTimeout: finHardTimeout,
		finIdleTimeout: finIdleTimeout,
	}
}

func (a *LearnAction) ToOfAction() (openflow13.Action, error) {
	learnAction := openflow13.NewNXActionLearn()
	learnAction.IdleTimeout = a.idleTimeout
	learnAction.HardTimeout = a.hardTimeout
	learnAction.Priority = a.priority
	learnAction.Cookie = a.cookie
	learnAction.Flags = a.flags
	learnAction.TableID = a.tableID
	learnAction.FinIdleTimeout = a.finIdleTimeout
	learnAction.FinHardTimeout = a.finHardTimeout
	learnAction.LearnSpecs = a.specs
	return learnAction, nil
}

func (a *LearnAction) GetActionType() string {
	return ActTypeNXLearn
}

func (a *LearnAction) AddLearnedLoadAction(learnDstField *LearnField, learnBitLen uint16, learnSrcField *LearnField, learnSrcValue []byte) error {
	dstMatchField, err := openflow13.FindFieldHeaderByName(learnDstField.Name, true)
	if err != nil {
		return err
	}
	dstField := &openflow13.NXLearnSpecField{
		Field: dstMatchField,
		Ofs:   learnDstField.Start,
	}

	var learnSpec *openflow13.NXLearnSpec
	if learnSrcValue != nil {
		header := openflow13.NewLearnHeaderLoadFromValue(learnBitLen)
		learnSpec = getLearnSpecWithValue(header, dstField, learnSrcValue)
	} else {
		header := openflow13.NewLearnHeaderLoadFromField(learnBitLen)
		srcMatchField, err := openflow13.FindFieldHeaderByName(learnSrcField.Name, true)
		if err != nil {
			return err
		}
		srcField := &openflow13.NXLearnSpecField{
			Field: srcMatchField,
			Ofs:   learnSrcField.Start,
		}
		learnSpec = getLearnSpecWithField(header, dstField, srcField)
	}

	a.specs = append(a.specs, learnSpec)

	return nil
}

func (a *LearnAction) SetDeleteLearned() {
	a.flags |= openflow13.NX_LEARN_F_DELETE_LEARNED
}

func (a *LearnAction) AddLearnedOutputAction(learnSrcField *LearnField, learnBitLen uint16) error {
	srcMatchField, err := openflow13.FindFieldHeaderByName(learnSrcField.Name, true)
	if err != nil {
		return err
	}
	srcField := &openflow13.NXLearnSpecField{
		Field: srcMatchField,
		Ofs:   learnSrcField.Start,
	}
	header := openflow13.NewLearnHeaderOutputFromField(learnBitLen)

	learnSpec := &openflow13.NXLearnSpec{
		Header:   header,
		SrcField: srcField,
	}

	a.specs = append(a.specs, learnSpec)

	return nil
}

func (a *LearnAction) AddLearnedMatch(learnDstField *LearnField, learnBitLen uint16, learnSrcField *LearnField, learnSrcValue []byte) error {
	dstMatchField, err := openflow13.FindFieldHeaderByName(learnDstField.Name, true)
	if err != nil {
		return err
	}

	dstField := &openflow13.NXLearnSpecField{
		Field: dstMatchField,
		Ofs:   learnDstField.Start,
	}

	var learnSpec *openflow13.NXLearnSpec
	if learnSrcValue != nil {
		header := openflow13.NewLearnHeaderMatchFromValue(learnBitLen)
		learnSpec = getLearnSpecWithValue(header, dstField, learnSrcValue)
	} else {
		header := openflow13.NewLearnHeaderMatchFromField(learnBitLen)
		srcMatchField, err := openflow13.FindFieldHeaderByName(learnSrcField.Name, true)
		if err != nil {
			return err
		}
		srcField := &openflow13.NXLearnSpecField{
			Field: srcMatchField,
			Ofs:   learnSrcField.Start,
		}
		learnSpec = getLearnSpecWithField(header, dstField, srcField)
	}

	a.specs = append(a.specs, learnSpec)

	return nil
}

func getLearnSpecWithValue(header *openflow13.NXLearnSpecHeader, dstField *openflow13.NXLearnSpecField, srcValue []byte) *openflow13.NXLearnSpec {
	return &openflow13.NXLearnSpec{
		Header:   header,
		DstField: dstField,
		SrcValue: srcValue,
	}
}

func getLearnSpecWithField(header *openflow13.NXLearnSpecHeader, dstField *openflow13.NXLearnSpecField, srcField *openflow13.NXLearnSpecField) *openflow13.NXLearnSpec {
	return &openflow13.NXLearnSpec{
		Header:   header,
		DstField: dstField,
		SrcField: srcField,
	}
}

type NXLoadAction struct {
	Field    *openflow13.MatchField
	Value    uint64
	Range    *openflow13.NXRange
	Appended bool
}

func NewNXLoadAction(fieldName string, data uint64, dataRange *openflow13.NXRange) (*NXLoadAction, error) {
	field, err := openflow13.FindFieldHeaderByName(fieldName, true)
	if err != nil {
		return nil, err
	}

	return &NXLoadAction{
		Field: field,
		Range: dataRange,
		Value: data,
	}, nil
}

func NewAppendedNXLoadAction(fieldName string, data uint64, dataRange *openflow13.NXRange) (*NXLoadAction, error) {
	field, err := openflow13.FindFieldHeaderByName(fieldName, true)
	if err != nil {
		return nil, err
	}

	return &NXLoadAction{
		Field:    field,
		Range:    dataRange,
		Value:    data,
		Appended: true,
	}, nil
}

func (a *NXLoadAction) ToOfAction() (openflow13.Action, error) {
	ofsBits := a.Range.ToOfsBits()
	return openflow13.NewNXActionRegLoad(ofsBits, a.Field, a.Value), nil
}

func (a *NXLoadAction) GetActionType() string {
	return ActTypeNXLoad
}

type NXMoveAction struct {
	Length    uint16
	SrcOffset uint16
	DstOffset uint16
	SrcField  *openflow13.MatchField
	DstField  *openflow13.MatchField
}

func NewNXMoveAction(bitLen, srcOffset, dstOffset uint16, srcMatchFieldName, dstMatchFieldName string, hasMask bool) (*NXMoveAction, error) {
	srcMatchField, err := openflow13.FindFieldHeaderByName(srcMatchFieldName, hasMask)
	if err != nil {
		return nil, err
	}
	dstMatchField, err := openflow13.FindFieldHeaderByName(dstMatchFieldName, hasMask)
	if err != nil {
		return nil, err
	}

	return &NXMoveAction{
		Length:    bitLen,
		SrcOffset: srcOffset,
		DstOffset: dstOffset,
		SrcField:  srcMatchField,
		DstField:  dstMatchField,
	}, nil
}

func (a *NXMoveAction) ToOfAction() (openflow13.Action, error) {
	return openflow13.NewNXActionRegMove(a.Length, a.SrcOffset, a.DstOffset, a.SrcField, a.DstField), nil
}

func (a *NXMoveAction) GetActionType() string {
	return ActTypeNXMove
}

type GroupAction struct {
	groupID uint32
}

func NewGroupAction(groupID uint32) *GroupAction {
	return &GroupAction{groupID}
}

func (a *GroupAction) ToOfAction() (openflow13.Action, error) {
	return openflow13.NewActionGroup(a.groupID), nil
}

func (a *GroupAction) GetActionType() string {
	return ActTypeGroup
}

type PortRange struct {
	portMin uint16
	portMax uint16
}

func NewPortRange(portMin uint16, portMax ...uint16) *PortRange {
	pr := &PortRange{
		portMin: portMin,
		portMax: portMin,
	}
	if len(portMax) > 0 {
		pr.portMax = portMax[0]
	}
	return pr
}

type IPRange struct {
	ipMin net.IP
	ipMax net.IP
}

func NewIPRange(ipMin net.IP, ipMax ...net.IP) *IPRange {
	ipR := &IPRange{
		ipMin: ipMin,
		ipMax: ipMin,
	}
	if len(ipMax) > 0 {
		ipR.ipMax = ipMax[0]
	}
	return ipR
}

func (i *IPRange) IsIPv6() bool {
	if i == nil {
		return false
	}
	if i.ipMin == nil {
		return false
	}
	return i.ipMin.To4() == nil
}

type NXCTNatAction struct {
	isSNat    bool
	isDnat    bool
	portRange *PortRange
	ipRange   *IPRange
}

func NewNatAction() *NXCTNatAction {
	return &NXCTNatAction{}
}

func NewSNatAction(ipr *IPRange, pr *PortRange) *NXCTNatAction {
	return &NXCTNatAction{
		isSNat:    true,
		ipRange:   ipr,
		portRange: pr,
	}
}

func NewDNatAction(ipr *IPRange, pr *PortRange) *NXCTNatAction {
	return &NXCTNatAction{
		isDnat:    true,
		ipRange:   ipr,
		portRange: pr,
	}
}

func (n *NXCTNatAction) GetActionType() string {
	return ActTypeCTNAT
}

func (n *NXCTNatAction) ToOfAction() (openflow13.Action, error) {
	act := openflow13.NewNXActionCTNAT()
	if n.isSNat {
		act.SetSNAT()
	}
	if n.isDnat {
		act.SetDNAT()
	}
	if n.ipRange != nil {
		if n.ipRange.IsIPv6() {
			act.SetRangeIPv6Min(n.ipRange.ipMin)
			act.SetRangeIPv6Max(n.ipRange.ipMax)
		} else {
			act.SetRangeIPv4Min(n.ipRange.ipMin)
			act.SetRangeIPv4Max(n.ipRange.ipMax)
		}
	}
	if n.portRange != nil {
		act.SetRangeProtoMin(&n.portRange.portMin)
		act.SetRangeProtoMax(&n.portRange.portMax)
	}

	return act, nil
}

type DecTtlAction struct {
	ActionType string
}

func (d *DecTtlAction) GetActionType() string {
	return d.ActionType
}

func (d *DecTtlAction) ToOfAction() (openflow13.Action, error) {
	return openflow13.NewActionDecNwTtl(), nil
}

func NewDecNwTtlAction(actionType string) *DecTtlAction {
	return &DecTtlAction{ActionType: actionType}
}
