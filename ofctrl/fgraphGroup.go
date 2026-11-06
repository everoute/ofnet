package ofctrl

import (
	openflow "github.com/contiv/libOpenflow/openflow15"
	log "github.com/sirupsen/logrus"
)

type Group struct {
	Switch      *OFSwitch
	GroupID     uint32
	GroupType   uint8
	Buckets     []*Bucket
	isInstalled bool
}

func (self *Group) Type() string {
	return "group"
}

func (self *Group) GetFlowInstr() openflow.Instruction {
	groupInstr := openflow.NewInstrApplyActions()
	groupAct := openflow.NewActionGroup(self.GroupID)
	groupInstr.AddAction(groupAct, false)

	return groupInstr
}

func newGroup(groupID uint32, groupType uint8, ofSwitch *OFSwitch) *Group {
	return &Group{
		Switch:      ofSwitch,
		GroupID:     groupID,
		GroupType:   groupType,
		isInstalled: false,
	}
}

func DeleteGroup(ofSwitch *OFSwitch, groupID uint32) error {
	groupMod := openflow.NewGroupMod()
	groupMod.GroupId = groupID
	groupMod.Command = openflow.OFPGC_DELETE

	if err := ofSwitch.Send(groupMod); err != nil {
		return err
	}

	ofSwitch.DeleteGroup(groupID)

	return nil
}

func (self *Group) Delete() {
	if self.isInstalled {
		groupMod := openflow.NewGroupMod()
		groupMod.GroupId = self.GroupID
		groupMod.Command = openflow.OFPGC_DELETE
		_ = self.Switch.Send(groupMod)
		// Mark it as unInstalled
		self.isInstalled = false
	}

	// Delete group from switch cache
	self.Switch.DeleteGroup(self.GroupID)
}

func (self *Group) Install() error {
	groupMod := openflow.NewGroupMod()
	groupMod.GroupId = self.GroupID

	// Change the OP to modify if it was already installed
	if self.isInstalled {
		groupMod.Command = openflow.OFPGC_MODIFY
	}

	// OF type for flood list
	groupMod.Type = self.GroupType

	// Add the bucket to groupMod
	for idx, bkt := range self.Buckets {
		ofBkt, err := bkt.toOfBucket(uint32(idx))
		if err != nil {
			log.Errorf("Invalid bucket: %+v, err is %s", *bkt, err)
			return err
		}
		groupMod.AddBucket(*ofBkt)
	}

	log.Debugf("Installing Group entry: %+v", groupMod)

	// Send it to the switch
	// indirect group must contain at least one bucket, otherwise, it will install failed
	if err := self.Switch.Send(groupMod); err != nil {
		return err
	}

	// Mark it as installed
	self.isInstalled = true

	return nil
}

func (self *Group) AddBucket(bkt *Bucket) {
	if self.Buckets == nil {
		self.Buckets = make([]*Bucket, 0)
	}
	self.Buckets = append(self.Buckets, bkt)

	if self.isInstalled {
		self.Install()
	}
}

func (self *Group) ResetBuckets(bkts []*Bucket) {
	self.Buckets = make([]*Bucket, 0)
	self.Buckets = append(self.Buckets, bkts...)

	if self.isInstalled {
		self.Install()
	}
}

type Bucket struct {
	weight        uint16
	bucketActions []Action
}

func NewBucket(weight ...uint16) *Bucket {
	var wei uint16
	if len(weight) >= 1 {
		wei = weight[0]
	}
	return &Bucket{
		weight:        wei,
		bucketActions: make([]Action, 0),
	}
}

func (self *Bucket) AddAction(act Action) {
	switch act.GetActionType() {
	case ActTypeNXResubmit, ActTypeOutput, ActTypeController, ActTypeGroup:
		self.bucketActions = append(self.bucketActions, act)
	default:
		self.bucketActions = append([]Action{act}, self.bucketActions...)
	}
}

func (self *Bucket) toOfBucket(id uint32) (*openflow.Bucket, error) {
	ofBkt := openflow.NewBucket(id)
	// In OpenFlow 1.5 the bucket weight is carried as a bucket property
	// (ofp_group_bucket_prop_weight) instead of an inline field.
	if self.weight != 0 {
		ofBkt.AddProperty(openflow.NewGroupBucketPropWeight(self.weight))
	}
	for i := range self.bucketActions {
		act, err := self.bucketActions[i].ToOfAction()
		if err != nil {
			return nil, err
		}
		ofBkt.AddAction(act)
	}
	ofBkt.Length = ofBkt.Len()

	return ofBkt, nil
}
