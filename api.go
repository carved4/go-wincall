package wincall

import (
	"fmt"
	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/resolve"
	"github.com/carved4/go-wincall/pkg/wincall"
)


var CallWorker = wincall.CallWorker
func LoadLibraryW(name string) uintptr {
	return wincall.LoadLibraryW(name)
}
var GetProcAddress = wincall.GetProcAddress
func UTF16PtrFromString(s string) (*uint16, error) {
	return wincall.UTF16PtrFromString(s)
}
var GetModuleBase = resolve.GetModuleBase
var GetFunctionAddress = resolve.GetFunctionAddress
var GetHash = obf.DBJ2HashStr
func Call(dllName, funcName string, args ...uintptr) (uintptr, error) {
	dllHash := GetHash(dllName) 
	moduleBase := GetModuleBase(dllHash)
	if moduleBase == 0 {
		moduleBase = wincall.LoadLibraryW(dllName)
		if moduleBase == 0 {
			return 0, fmt.Errorf("failed to load DLL: %s", dllName)
		}
	}
	funcHash := GetHash(funcName) 
	funcAddr := GetFunctionAddress(moduleBase, funcHash)
	if funcAddr == 0 {
		return 0, fmt.Errorf("failed to resolve function: %s in %s", funcName, dllName)
	}
	
	// Explicitly capture result to ensure proper return value propagation
	// This prevents compiler optimization issues that can cause return value loss
	result, err := wincall.CallWorker(funcAddr, args...)
	if err != nil {
		return 0, err
	}
	return result, nil
}

func UTF16ptr(s string) (*uint16, error){
	ptr, err := wincall.UTF16PtrFromString(s)
	return ptr, err
}

// NT* syscall wrappers
func NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uintptr, protect uintptr) (uint32, error) {
	return wincall.NtAllocateVirtualMemory(processHandle, baseAddress, zeroBits, regionSize, allocationType, protect)
}

func NtWriteVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer uintptr, numberOfBytesToWrite uintptr, numberOfBytesWritten *uintptr) (uint32, error) {
	return wincall.NtWriteVirtualMemory(processHandle, baseAddress, buffer, numberOfBytesToWrite, numberOfBytesWritten)
}

func NtReadVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer uintptr, numberOfBytesToRead uintptr, numberOfBytesRead *uintptr) (uint32, error) {
	return wincall.NtReadVirtualMemory(processHandle, baseAddress, buffer, numberOfBytesToRead, numberOfBytesRead)
}

func NtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uintptr, oldProtect *uintptr) (uint32, error) {
	return wincall.NtProtectVirtualMemory(processHandle, baseAddress, regionSize, newProtect, oldProtect)
}

func NtCreateEvent(eventHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, eventType uintptr, initialState bool) (uint32, error) {
	return wincall.NtCreateEvent(eventHandle, desiredAccess, objectAttributes, eventType, initialState)
}

func NtSetEvent(eventHandle uintptr, previousState *uintptr) (uint32, error) {
	return wincall.NtSetEvent(eventHandle, previousState)
}

func NtCreateThreadEx(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, parameter uintptr, createFlags uintptr, stackZeroBits uintptr, stackCommitSize uintptr, stackReserveSize uintptr, attributeList uintptr) (uint32, error) {
	return wincall.NtCreateThreadEx(threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createFlags, stackZeroBits, stackCommitSize, stackReserveSize, attributeList)
}

func NtWaitForSingleObject(handle uintptr, alertable bool, timeout *int64) (uint32, error) {
	return wincall.NtWaitForSingleObject(handle, alertable, timeout)
}
