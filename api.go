package wincall

import (
	"unicode/utf16"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/errors"
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
var GetHash = obf.GetHash

func Call(dllName, funcName interface{}, args ...interface{}) (uintptr, error) {
	// Convert parameters to strings (handles both string and obfuscated formats)
	var dllNameStr, funcNameStr string
	
	switch v := dllName.(type) {
	case string:
		dllNameStr = v
	default:
		dllNameStr = v.(string)
	}
	
	switch v := funcName.(type) {
	case string:
		funcNameStr = v
	default:
		funcNameStr = v.(string)
	}
	
	dllHash := GetHash(dllNameStr)
	moduleBase := GetModuleBase(dllHash)
	if moduleBase == 0 {
		moduleBase = wincall.LoadLibraryW(dllNameStr)
		if moduleBase == 0 {
			return 0, errors.New(errors.Err1)
		}
	}
	funcHash := GetHash(funcNameStr)
	funcAddr := GetFunctionAddress(moduleBase, funcHash)
	if funcAddr == 0 {
		return 0, errors.New(errors.Err2)
	}

	result, err := wincall.CallWorker(funcAddr, args...)
	if err != nil {
		return 0, err
	}
	return result, nil
}

func UTF16ptr(s string) (*uint16, error) {
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

// Generic bit manipulation helpers for unpacking most Windows API return values

// ExtractByte extracts a specific byte from a return value
// byteIndex: 0=lowest byte, 1=second byte, etc.
// Example: ExtractByte(result, 0) gets bits 0-7
func ExtractByte(value uintptr, byteIndex int) uint8 {
	return uint8((value >> (byteIndex * 8)) & 0xFF)
}

// ExtractWord extracts a specific 16-bit word from a return value
// wordIndex: 0=low word (bits 0-15), 1=high word (bits 16-31)
func ExtractWord(value uintptr, wordIndex int) uint16 {
	return uint16((value >> (wordIndex * 16)) & 0xFFFF)
}

// ExtractBits extracts arbitrary bit range from a return value
// startBit: starting bit position (0-based from right)
// numBits: number of bits to extract (1-32)
// Example: ExtractBits(result, 8, 4) gets bits 8-11
func ExtractBits(value uintptr, startBit, numBits int) uint32 {
	mask := (uint32(1) << numBits) - 1
	return uint32(value>>startBit) & mask
}

// CombineWords combines two 16-bit words into 32-bit value
func CombineWords(low, high uint16) uint32 {
	return uint32(high)<<16 | uint32(low)
}

// CombineBytes combines four bytes into 32-bit value
func CombineBytes(b0, b1, b2, b3 uint8) uint32 {
	return uint32(b3)<<24 | uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
}

// CombineDwords combines two 32-bit values into 64-bit
func CombineDwords(low, high uint32) uint64 {
	return uint64(high)<<32 | uint64(low)
}

// SplitDwords splits 64-bit value into two 32-bit parts
func SplitDwords(value uint64) (low, high uint32) {
	return uint32(value & 0xFFFFFFFF),
		uint32((value >> 32) & 0xFFFFFFFF)
}

// ReadUTF16String reads a null-terminated UTF-16 string from a memory pointer
// Used for APIs that return LPWSTR/LPCWSTR pointers like GetCommandLineW
func ReadUTF16String(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var chars []uint16
	offset := uintptr(0)

	for {
		char := *(*uint16)(unsafe.Pointer(ptr + offset))
		if char == 0 {
			break
		}
		chars = append(chars, char)
		offset += 2

		if len(chars) > 32768 {
			break
		}
	}
	return string(utf16.Decode(chars))
}

// ReadANSIString reads a null-terminated ANSI string from a memory pointer
// Used for APIs that return LPSTR/LPCSTR pointers
func ReadANSIString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}

	var bytes []byte
	offset := uintptr(0)

	for {
		b := *(*byte)(unsafe.Pointer(ptr + offset))
		if b == 0 {
			break
		}
		bytes = append(bytes, b)
		offset++

		if len(bytes) > 32768 {
			break
		}
	}

	return string(bytes)
}

// ReadLARGE_INTEGER reads a 64-bit value from a LARGE_INTEGER structure pointer
func ReadLARGE_INTEGER(ptr uintptr) int64 {
	if ptr == 0 {
		return 0
	}
	return *(*int64)(unsafe.Pointer(ptr))
}

// ReadBytes reads a byte array from a memory pointer
func ReadBytes(ptr uintptr, length int) []byte {
	if ptr == 0 || length <= 0 {
		return nil
	}

	bytes := make([]byte, length)
	for i := 0; i < length; i++ {
		bytes[i] = *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
	}
	return bytes
}
