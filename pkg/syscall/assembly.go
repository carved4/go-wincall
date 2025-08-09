package syscall

import (
	"github.com/carved4/go-wincall/pkg/errors"
)

//go:noescape
func do_syscall(callid uint16, argh ...uintptr) uint32

//go:noescape
func do_syscall_indirect(ssn uint16, trampoline uintptr, argh ...uintptr) uint32

//go:noescape
func getTrampoline(stubAddr uintptr) uintptr




func Syscall(syscallNum uint16, args ...uintptr) (uintptr, error) {
	result := do_syscall(syscallNum, args...)
	return uintptr(result), nil
}

func IndirectSyscall(syscallNum uint16, syscallAddr uintptr, args ...uintptr) (uintptr, error) {
	trampoline := getTrampoline(syscallAddr)
	if trampoline == 0 {
		return 0, errors.New(errors.Err1)
	}

	result := do_syscall_indirect(syscallNum, trampoline, args...)
	return uintptr(result), nil
}

