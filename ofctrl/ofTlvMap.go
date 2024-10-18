package ofctrl

import (
	"fmt"
	"time"

	"github.com/contiv/libOpenflow/openflow13"
)

const (
	messageTimeout = 10 * time.Second
)

type TLVTableStatus openflow13.TLVTableReply

type TLVStatusManager interface {
	TLVMapReplyRcvd(ofSwitch *OFSwitch, status *TLVTableStatus)
}

func (t *TLVTableStatus) GetTLVMap(index uint16) *openflow13.TLVTableMap {
	for _, m := range t.TlvMaps {
		if m.Index == index {
			return m
		}
	}
	return nil
}

func (t *TLVTableStatus) GetMaxSpace() uint32 {
	return t.MaxSpace
}

func (t *TLVTableStatus) GetMaxFields() uint16 {
	return t.MaxFields
}

func (t *TLVTableStatus) GetAllocatedResources() (space uint32, indexes []uint16) {
	for _, m := range t.TlvMaps {
		space += uint32(m.OptLength)
		indexes = append(indexes, m.Index)
	}
	return
}

func (t *TLVTableStatus) String() string {
	value := fmt.Sprintf("max option space=%d max field=%d\n", t.MaxSpace, t.MaxFields)
	for _, m := range t.TlvMaps {
		value = fmt.Sprintf("%s%s", value, t.GetTLVMapString(m))
	}
	return value
}

func (t *TLVTableStatus) GetTLVMapString(m *openflow13.TLVTableMap) string {
	return fmt.Sprintf("TLVMap: class=0x%x,type=0x%x,length=0x%x,match_field=%d", m.OptClass, m.OptType, m.OptLength, m.Index)
}

func (t *TLVTableStatus) AddTLVMap(m *openflow13.TLVTableMap) {
	t.TlvMaps = append(t.TlvMaps, m)
}

func (s *OFSwitch) AddTunnelTLVMap(optClass uint16, optType uint8, optLength uint8, tunMetadataIndex uint16) error {
	tlvMap := s.tlvMgr.status.GetTLVMap(tunMetadataIndex)
	if tlvMap != nil {
		if tlvMap.OptClass != optClass {
			return fmt.Errorf("another tlv-map is using the same tun_metadata with Class %d", tlvMap.OptClass)
		}
		if tlvMap.OptType != optType {
			return fmt.Errorf("another tlv-map is using the same tun_metadata with Type %d", tlvMap.OptType)
		}
		if tlvMap.OptLength != optLength {
			return fmt.Errorf("another tlv-map is using the same tun_metadata with Length: %d", tlvMap.OptLength)
		}
		return nil
	}
	tlvMap = &openflow13.TLVTableMap{
		OptClass:  optClass,
		OptType:   optType,
		OptLength: optLength,
		Index:     tunMetadataIndex,
	}
	tlvMaps := []*openflow13.TLVTableMap{
		{
			OptClass:  optClass,
			OptType:   optType,
			OptLength: optLength,
			Index:     tunMetadataIndex,
		},
	}
	tlvMapMod := openflow13.NewTLVTableMod(openflow13.NXTTMC_ADD, tlvMaps)
	msg := openflow13.NewTLVTableModMessage(tlvMapMod)
	s.Send(msg)
	s.tlvMgr.status.AddTLVMap(tlvMap)
	return nil
}

func (s *OFSwitch) DeleteTunnelTLVMap(tlvMaps []*openflow13.TLVTableMap) {
	tlvMapMod := openflow13.NewTLVTableMod(openflow13.NXTTMC_DELETE, tlvMaps)
	msg := openflow13.NewTLVTableModMessage(tlvMapMod)
	s.Send(msg)
}

func (s *OFSwitch) ClearTunnelTLVMap(tlvMaps []*openflow13.TLVTableMap) {
	tlvMapMod := openflow13.NewTLVTableMod(openflow13.NXTTMC_CLEAR, tlvMaps)
	msg := openflow13.NewTLVTableModMessage(tlvMapMod)
	s.Send(msg)
}

func ResetFieldLength(field *openflow13.MatchField, tlvMapStatus *TLVTableStatus) *openflow13.MatchField {
	if tlvMapStatus == nil {
		return field
	}
	if field.Class != openflow13.OXM_CLASS_NXM_1 {
		return field
	}
	if field.Field < openflow13.NXM_NX_TUN_METADATA0 || field.Field > openflow13.NXM_NX_TUN_METADATA7 {
		return field
	}
	index := field.Field - openflow13.NXM_NX_TUN_METADATA0
	m := tlvMapStatus.GetTLVMap(uint16(index))
	if m != nil {
		field.Length = m.OptLength
	}
	return field
}

func (s *OFSwitch) ResetFieldLength(field *openflow13.MatchField) *openflow13.MatchField {
	if s.tlvMgr.status == nil {
		return field
	}
	if field.Field < openflow13.NXM_NX_TUN_METADATA0 || field.Field > openflow13.NXM_NX_TUN_METADATA7 {
		return field
	}
	index := field.Field - openflow13.NXM_NX_TUN_METADATA0
	m := s.tlvMgr.status.GetTLVMap(uint16(index))
	if m != nil {
		field.Length = m.OptLength
	}
	return field
}

func (s *OFSwitch) GetTLVMapTableStatus() *TLVTableStatus {
	if s.tlvMgr == nil {
		return nil
	}
	return s.tlvMgr.status
}

type tlvMapMgr struct {
	status *TLVTableStatus
	tlvCh  chan struct{}
}

func (m *tlvMapMgr) TLVMapReplyRcvd(ofSwitch *OFSwitch, status *TLVTableStatus) {
	m.status = status
	m.tlvCh <- struct{}{}
}

func (s *OFSwitch) requestTlvMap() error {
	if s.tlvMgr == nil {
		return nil
	}
	msg := openflow13.NewTLVTableRequest()

	var err error
	s.Send(msg)

	select {
	case <-s.tlvMgr.tlvCh:
		return nil
	case <-time.After(messageTimeout):
		err = fmt.Errorf("tlv-map request is not replied on switch %s in 10s", s.dpid.String())
	case <-s.ctx.Done():
		err = fmt.Errorf("cancel the wait for tlv-map reply because switch %s is diconnected", s.dpid.String())

	}
	return err
}

func newTLVMapMgr() *tlvMapMgr {
	mgr := new(tlvMapMgr)
	mgr.tlvCh = make(chan struct{}, 1)
	return mgr
}
