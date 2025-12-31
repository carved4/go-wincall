//go:build windows && amd64

package syscall

//go:noescape
func do_syscall(callid uint32, argh ...uintptr) uint32

//go:noescape
func do_syscall_indirect(ssn uint32, trampoline uintptr, argh ...uintptr) uint32

//go:noescape
func GetTrampoline(stubAddr uintptr) uintptr

func Syscall(syscallNum uint32, args ...uintptr) (uintptr, error) {
	result := do_syscall(syscallNum, args...)
	return uintptr(result), nil
}

func IndirectSyscall(ssn uint32, trampoline uintptr, args ...uintptr) (uintptr, error) {
	if trampoline == 0 {
		return Syscall(ssn, args...)
	}
	result := do_syscall_indirect(ssn, trampoline, args...)
	return uintptr(result), nil
}
