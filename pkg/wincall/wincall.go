package wincall

import (
    "sync"
    "unsafe"

    "github.com/carved4/go-wincall/pkg/errors"
    "github.com/carved4/go-wincall/pkg/obf"
    "github.com/carved4/go-wincall/pkg/resolve"
    "github.com/carved4/go-wincall/pkg/syscall"
)

var (
    ntAllocateVirtualMemoryNum    uint16
    ntAllocateVirtualMemoryAddr   uintptr
    ntWriteVirtualMemoryNum       uint16
    ntWriteVirtualMemoryAddr      uintptr
    ntReadVirtualMemoryNum        uint16
    ntReadVirtualMemoryAddr       uintptr
    ntProtectVirtualMemoryNum     uint16
    ntProtectVirtualMemoryAddr    uintptr
    ntQueryInformationThreadNum   uint16
    ntQueryInformationThreadAddr  uintptr
    ntQueryInformationProcessNum  uint16
    ntQueryInformationProcessAddr uintptr
    resolveSyscallsOnce           sync.Once
)

func resolveSyscalls() {
    ntAllocateVirtualMemoryNum, ntAllocateVirtualMemoryAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtAllocateVirtualMemory"))
    ntWriteVirtualMemoryNum, ntWriteVirtualMemoryAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtWriteVirtualMemory"))
    ntReadVirtualMemoryNum, ntReadVirtualMemoryAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtReadVirtualMemory"))
    ntProtectVirtualMemoryNum, ntProtectVirtualMemoryAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtProtectVirtualMemory"))
    ntQueryInformationThreadNum, ntQueryInformationThreadAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtQueryInformationThread"))
    ntQueryInformationProcessNum, ntQueryInformationProcessAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtQueryInformationProcess"))
}

func NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uintptr, protect uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntAllocateVirtualMemoryNum == 0 {
		return 0xC0000139, errors.New(errors.Err1)
	}
	ret, err := syscall.IndirectSyscall(ntAllocateVirtualMemoryNum, ntAllocateVirtualMemoryAddr,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		allocationType,
		protect,
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtWriteVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer uintptr, numberOfBytesToWrite uintptr, numberOfBytesWritten *uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntWriteVirtualMemoryNum == 0 {
		return 0xC0000139, errors.New(errors.Err1)
	}
	ret, err := syscall.IndirectSyscall(ntWriteVirtualMemoryNum, ntWriteVirtualMemoryAddr,
		processHandle,
		baseAddress,
		buffer,
		numberOfBytesToWrite,
		uintptr(unsafe.Pointer(numberOfBytesWritten)),
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtReadVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer uintptr, numberOfBytesToRead uintptr, numberOfBytesRead *uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntReadVirtualMemoryNum == 0 {
		return 0xC0000139, errors.New(errors.Err1)
	}
	ret, err := syscall.IndirectSyscall(ntReadVirtualMemoryNum, ntReadVirtualMemoryAddr,
		processHandle,
		baseAddress,
		buffer,
		numberOfBytesToRead,
		uintptr(unsafe.Pointer(numberOfBytesRead)),
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uintptr, oldProtect *uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntProtectVirtualMemoryNum == 0 {
		return 0xC0000139, errors.New(errors.Err1)
	}
	ret, err := syscall.IndirectSyscall(ntProtectVirtualMemoryNum, ntProtectVirtualMemoryAddr,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		newProtect,
		uintptr(unsafe.Pointer(oldProtect)),
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

// Removed unused Nt* wrappers for events/threads waiting/creation.

// ThreadBasicInformation structure for NtQueryInformationThread
type ThreadBasicInformation struct {
	ExitStatus      uint32
	TebBaseAddress  uintptr
	ClientIdProcess uintptr
	ClientIdThread  uintptr
	AffinityMask    uintptr
	Priority        uint32
	BasePriority    uint32
}

func NtQueryInformationThread(threadHandle uintptr, threadInformationClass uintptr, threadInformation uintptr, threadInformationLength uintptr, returnLength *uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntQueryInformationThreadNum == 0 {
		return 0xC0000139, errors.New(errors.Err1)
	}
	ret, err := syscall.IndirectSyscall(ntQueryInformationThreadNum, ntQueryInformationThreadAddr,
		threadHandle,
		threadInformationClass,
		threadInformation,
		threadInformationLength,
		uintptr(unsafe.Pointer(returnLength)),
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func GetCurrentThreadId() (uint32, error) {
	// Get current thread handle
	const getCurrentThread = uintptr(0xFFFFFFFFFFFFFFFE) // Current thread pseudo-handle
	const threadBasicInformation = 0

	var tbi ThreadBasicInformation
	var returnLength uintptr

	status, err := NtQueryInformationThread(
		getCurrentThread,
		threadBasicInformation,
		uintptr(unsafe.Pointer(&tbi)),
		uintptr(unsafe.Sizeof(tbi)),
		&returnLength,
	)

	if err != nil || status != 0 {
		return 0, errors.New(errors.Err1)
	}

	return uint32(tbi.ClientIdThread), nil
}

func NtQueryInformationProcess(processHandle uintptr, processInformationClass uintptr, processInformation uintptr, processInformationLength uintptr, returnLength *uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntQueryInformationProcessNum == 0 {
		return 0xC0000139, errors.New(errors.Err1)
	}
	ret, err := syscall.IndirectSyscall(ntQueryInformationProcessNum, ntQueryInformationProcessAddr,
		processHandle,
		processInformationClass,
		processInformation,
		processInformationLength,
		uintptr(unsafe.Pointer(returnLength)),
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

// (all worker-thread code removed)
