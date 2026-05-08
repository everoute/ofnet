package ofctrl

type MessageType int

const (
	UnknownMessage MessageType = iota
	BundleControlMessage
	BundleAddMessage
)

type MessageResult struct {
	succeed      bool
	errType      uint16
	errCode      uint16
	experimenter int32
	xID          uint32
	msgType      MessageType
}

func (r *MessageResult) IsSucceed() bool {
	return r.succeed
}

func (r *MessageResult) GetErrorType() uint16 {
	return r.errType
}

func (r *MessageResult) GetErrorCode() uint16 {
	return r.errCode
}

func (r *MessageResult) GetExperimenterID() int32 {
	return r.experimenter
}

func (r *MessageResult) GetXid() uint32 {
	return r.xID
}
