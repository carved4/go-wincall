package syscall

import (
	"fmt"
	"runtime"

	"wincall/pkg/resolve"
)


// DoSyscallExternal calls the assembly function directly
func DoSyscallExternal(ssn uint16, nargs uint32, args ...uintptr) uintptr {
	// Lock the OS thread for syscall safety
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result := do_syscall(ssn, args...)
	return uintptr(result)
}

// ExternalSyscall is a wrapper that uses the assembly implementation
func ExternalSyscall(syscallNumber uint16, args ...uintptr) (uintptr, error) {
	result := DoSyscallExternal(syscallNumber, uint32(len(args)), args...)
	return result, nil
}

// HashSyscall executes a direct syscall using a function name hash
// This simplifies API calls by automatically resolving the syscall number
func HashSyscall(functionHash uint32, args ...uintptr) (uintptr, error) {
	syscallNum := resolve.GetSyscallNumber(functionHash)
	return ExternalSyscall(syscallNum, args...)
}

func HashSyscallIndirect(functionhash uint32, args ...uintptr) (uintptr, error) {
	syscallNum, syscallAddr := resolve.GetSyscallAndAddress(functionhash)
	result := DoIndirectSyscallExternal(syscallNum, syscallAddr, uint32(len(args)), args...)
	return result, nil
}
// DoIndirectSyscallExternal calls the assembly indirect function directly
func DoIndirectSyscallExternal(ssn uint16, syscallAddr uintptr, nargs uint32, args ...uintptr) uintptr {
	// Lock the OS thread for syscall safety
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Automatically resolve trampoline from the stub address
	trampoline := getTrampoline(syscallAddr)
	if trampoline == 0 {
		// Return error status if trampoline resolution fails
		return 0xC0000005 // STATUS_ACCESS_VIOLATION
	}

	result := do_syscall_indirect(ssn, trampoline, args...)
	return uintptr(result)
}

// This function is now defined in assembly.go

// HashIndirectSyscall executes an indirect syscall using a function name hash
func HashIndirectSyscall(functionHash uint32, args ...uintptr) (uintptr, error) {
	syscallNum, syscallAddr := resolve.GetSyscallAndAddress(functionHash)
	if syscallNum == 0 || syscallAddr == 0 {
		return 0, fmt.Errorf("failed to resolve syscall number or address for hash 0x%X", functionHash)
	}
	result := DoIndirectSyscallExternal(syscallNum, syscallAddr, uint32(len(args)), args...)
	return result, nil
}
