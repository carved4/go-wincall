package errors

import "fmt"

// error codes :3
const (
	ErrModuleNotFound   = 1
	ErrFunctionNotFound = 2
	ErrUnsupportedArg   = 3
)

type WinCallError struct {
	Code uint32
}

func (e *WinCallError) Error() string {
	switch e.Code {
	case ErrModuleNotFound:
		return "wincall: module not found"
	case ErrFunctionNotFound:
		return "wincall: function not found"
	case ErrUnsupportedArg:
		return "wincall: unsupported argument type"
	default:
		return fmt.Sprintf("wincall: error %d", e.Code)
	}
}

// New creates a new WinCallError
func New(code uint32) error {
	return &WinCallError{Code: code}
}

// IsCode checks if an error has a specific error code
func IsCode(err error, code uint32) bool {
	if wcErr, ok := err.(*WinCallError); ok {
		return wcErr.Code == code
	}
	return false
}
