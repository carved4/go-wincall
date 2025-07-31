package wincall

import (
	"fmt"
	"unsafe"
	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/resolve"
	"github.com/carved4/go-wincall/pkg/syscall"
)

//go:noescape
func wincall_winthread_entry() uintptr

//go:noescape
func wincall_get_winthread_entry_addr() uintptr



// NtCreateThreadEx wrapper
func NtCreateThreadEx(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, parameter uintptr, createFlags uintptr, stackZeroBits uintptr, stackCommitSize uintptr, stackReserveSize uintptr, attributeList uintptr) (uint32, error) {
	syscallNum, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtCreateThreadEx"))
	if syscallNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtCreateThreadEx") // STATUS_PROCEDURE_NOT_FOUND
	}

	ret, err := syscall.IndirectSyscall(syscallNum, syscallAddr,
		uintptr(unsafe.Pointer(threadHandle)),
		desiredAccess,
		objectAttributes,
		processHandle,
		startAddress,
		parameter,
		createFlags,
		stackZeroBits,
		stackCommitSize,
		stackReserveSize,
		attributeList,
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

// NtWaitForSingleObject wrapper
func NtWaitForSingleObject(handle uintptr, alertable bool, timeout *int64) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtWaitForSingleObject"))
	if syscallNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtWaitForSingleObject") // STATUS_PROCEDURE_NOT_FOUND
	}

	var alertableFlag uintptr
	if alertable {
		alertableFlag = 1
	}

	var timeoutPtr uintptr
	if timeout != nil {
		timeoutPtr = uintptr(unsafe.Pointer(timeout))
	}

	syscallNum2, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtWaitForSingleObject"))
	ret, err := syscall.IndirectSyscall(syscallNum2, syscallAddr, handle, alertableFlag, timeoutPtr)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func CallInNewThread(funcAddr uintptr, args ...uintptr) (uintptr, error) {
	lc := &libcall{
		fn: funcAddr,
		n:  uintptr(len(args)),
	}
	if len(args) > 0 {
		lc.args = uintptr(unsafe.Pointer(&args[0]))
	} else {
		lc.args = 0
	}

	var threadHandle uintptr
	status, err := NtCreateThreadEx(
		&threadHandle,                      // ThreadHandle
		0x1FFFFF,                          // DesiredAccess (THREAD_ALL_ACCESS)
		0,                                 // ObjectAttributes
		0xFFFFFFFFFFFFFFFF,                // ProcessHandle (-1 for current process)
		wincall_get_winthread_entry_addr(), // StartRoutine
		uintptr(unsafe.Pointer(lc)),       // Argument
		0,                                 // CreateFlags
		0,                                 // ZeroBits
		0,                                 // StackSize
		0,                                 // MaximumStackSize
		0,                                 // AttributeList
	)
	if err != nil {
		return 0, fmt.Errorf("NtCreateThreadEx syscall error: %v", err)
	}
	// Check NTSTATUS - 0 means STATUS_SUCCESS
	if status != 0 {
		return 0, fmt.Errorf("NtCreateThreadEx failed with NTSTATUS: 0x%x", status)
	}
	if threadHandle == 0 {
		return 0, fmt.Errorf("NtCreateThreadEx returned null thread handle")
	}

	// Wait for thread completion
	waitStatus, err := NtWaitForSingleObject(threadHandle, false, nil)
	if err != nil {
		return 0, fmt.Errorf("NtWaitForSingleObject failed: %v", err)
	}
	if waitStatus != 0 {
		return 0, fmt.Errorf("NtWaitForSingleObject returned status: 0x%x", waitStatus)
	}

	return lc.r1, nil
}
