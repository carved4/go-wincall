package errors

import "fmt"

// error codes :3
const (
	Err0 = 0
	Err1 = 1
	Err2 = 2
)

type WinCallError struct {
	Code uint32
}

func (e *WinCallError) Error() string {
	return fmt.Sprintf("%d", e.Code)
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
