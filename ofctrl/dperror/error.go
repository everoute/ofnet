package dperror

import (
	"fmt"
)

var (
	OK                      = &ErrorNo{Code: 0, Msg: "OK"}
	SwitchDisconnectedError = &ErrorNo{Code: 1000, Msg: "switch disconnected"}
	DefaultInternalError    = &ErrorNo{Code: 10000, Msg: "default internal error"}
)

type ErrorNo struct {
	Code int64
	Msg  string
}

type DpError struct {
	Msg  string
	Code int64
	Err  error
}

func (errorNo *ErrorNo) Error() string {
	return errorNo.Msg
}

func (dpError *DpError) Error() string {
	return fmt.Sprintf("Err-%v, code-%v, message-%v", dpError.Err, dpError.Code, dpError.Msg)
}

func NewDpError(errorCode int64, errorMsg string, err error) *DpError {
	return &DpError{
		Code: errorCode,
		Msg:  errorMsg,
		Err:  err,
	}
}

func DecodeError(err error) (int64, string) {
	if err == nil {
		return OK.Code, OK.Msg
	}

	switch errType := err.(type) {
	case *DpError:
		return errType.Code, errType.Msg
	case *ErrorNo:
		return errType.Code, errType.Msg
	default:
	}

	return DefaultInternalError.Code, DefaultInternalError.Msg
}
