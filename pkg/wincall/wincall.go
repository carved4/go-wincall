package wincall

import (
	"fmt"
	"unsafe"
	"wincall/pkg/obf"
	"wincall/pkg/syscall"
)

//go:noescape
func wincall_winthread_entry() uintptr

//go:noescape
func wincall_get_winthread_entry_addr() uintptr



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
	ntCreateThreadExHash := obf.GetHash("NtCreateThreadEx")
	_, err := syscall.HashSyscallIndirect(
		ntCreateThreadExHash,
		uintptr(unsafe.Pointer(&threadHandle)), // ThreadHandle
		0x1FFFFF,                              // DesiredAccess
		0,                                     // ObjectAttributes
		0xFFFFFFFFFFFFFFFF,                    // ProcessHandle (-1 for current process)
		wincall_get_winthread_entry_addr(),    // StartRoutine
		uintptr(unsafe.Pointer(lc)),           // Argument
		0,                                     // CreateFlags
		0,                                     // ZeroBits
		0,                                     // StackSize
		0,                                     // MaximumStackSize
		0,                                     // AttributeList
	)
	if err != nil || threadHandle == 0 {
		return 0, fmt.Errorf("NtCreateThreadEx failed: %v", err)
	}

	ntWaitForSingleObjectHash := obf.GetHash("NtWaitForSingleObject")
	_, err = syscall.HashSyscallIndirect(ntWaitForSingleObjectHash, threadHandle, 0, 0)

	return lc.r1, nil
}
