package ofctrl

import (
	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
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

func (self *Group) GetFlowInstr() openflow13.Instruction {
	groupInstr := openflow13.NewInstrApplyActions()
	groupAct := openflow13.NewActionGroup(self.GroupID)
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
	groupMod := openflow13.NewGroupMod()
	groupMod.GroupId = groupID
	groupMod.Command = openflow13.OFPGC_DELETE

	ofSwitch.Send(groupMod)

	ofSwitch.DeleteGroup(groupID)

	return nil
}

func (self *Group) Delete() {
	if self.isInstalled {
		groupMod := openflow13.NewGroupMod()
		groupMod.GroupId = self.GroupID
		groupMod.Command = openflow13.OFPGC_DELETE
		self.Switch.Send(groupMod)
		// Mark it as unInstalled
		self.isInstalled = false
	}

	// Delete group from switch cache
	self.Switch.DeleteGroup(self.GroupID)
}

func (self *Group) Install() error {
	groupMod := openflow13.NewGroupMod()
	groupMod.GroupId = self.GroupID

	// Change the OP to modify if it was already installed
	if self.isInstalled {
		groupMod.Command = openflow13.OFPGC_MODIFY
	}

	// OF type for flood list
	groupMod.Type = self.GroupType

	// Add the bucket to groupMod
	for _, bkt := range self.Buckets {
		ofBkt, err := bkt.toOfBucket()
		if err != nil {
			log.Errorf("Invalid bucket: %+v, err is %s", *bkt, err)
			return err
		}
		groupMod.AddBucket(*ofBkt)
	}

	log.Debugf("Installing Group entry: %+v", groupMod)

	// Send it to the switch
	// indirect group must contain at least one bucket, otherwise, it will install failed
	self.Switch.Send(groupMod)

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

func (self *Bucket) toOfBucket() (*openflow13.Bucket, error) {
	ofBkt := openflow13.NewBucket()
	ofBkt.Weight = self.weight
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
