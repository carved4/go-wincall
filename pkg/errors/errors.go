package errors

import "fmt"

// Error codes
const (
	Err0 = 0
	Err1 = 1
	Err2 = 2
)

// WinCallError represents an error with an error code
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
