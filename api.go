package wincall

import (
	"unicode/utf16"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/errors"
	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/resolve"
	pkgsys "github.com/carved4/go-wincall/pkg/syscall"
	"github.com/carved4/go-wincall/pkg/unhook"
	"github.com/carved4/go-wincall/pkg/utils"
	"github.com/carved4/go-wincall/pkg/wincall"
)

func init() {
	resolve.SetLoadLibraryCallback(wincall.LdrLoadDLL)
}

func CallG0(funcAddr uintptr, args ...any) (uintptr, uintptr, error) {
	return wincall.CallG0(funcAddr, args...)
}

func CurrentThreadIDFast() uint32 { return wincall.CurrentThreadIDFast() }

func RunOnG0(f func()) { wincall.RunOnG0(f) }

func LoadLibraryLdr(name string) uintptr {
	return wincall.LdrLoadDLL(name)
}

func GetModuleBase(moduleHash uint32) uintptr {
	return resolve.GetModuleBase(moduleHash)
}

func GetFunctionAddress(moduleBase uintptr, functionHash uint32) uintptr {
	return resolve.GetFunctionAddress(moduleBase, functionHash)
}

func GetHash(s string) uint32 {
	return obf.GetHash(s)
}

func IsDebuggerPresent() bool {
	return wincall.IsDebuggerPresent()
}

func Call(dllName, funcName interface{}, args ...interface{}) (uintptr, uintptr, error) {
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
		moduleBase = wincall.LoadDll(dllNameStr)
		if moduleBase == 0 {
			return 0, 0, errors.New(errors.Err1)
		}
	}
	funcHash := GetHash(funcNameStr)
	funcAddr := GetFunctionAddress(moduleBase, funcHash)
	if funcAddr == 0 {
		return 0, 0, errors.New(errors.Err2)
	}
	r1, r2, err := wincall.CallG0(funcAddr, args...)
	if err != nil {
		return 0, 0, err
	}
	return r1, r2, nil
}

func UTF16ptr(s string) (*uint16, error) {
	ptr, err := wincall.UTF16PtrFromString(s)
	return ptr, err
}

func UnhookNtdll() {
	unhook.UnhookNtdll()
}
func Syscall(syscallNum uint32, args ...uintptr) (uintptr, error) {
	return pkgsys.Syscall(syscallNum, args...)
}
func IndirectSyscall(syscallNum uint32, syscallAddr uintptr, args ...uintptr) (uintptr, error) {
	return pkgsys.IndirectSyscall(syscallNum, syscallAddr, args...)
}

func ClearCache() {
	resolve.ClearResolveCaches()
}

func GetSyscall(hash uint32) resolve.Syscall {
	return resolve.GetSyscall(hash)
}

// generic bit manipulation helpers for unpacking most windows api return values :3

// ExtractByte extracts a specific byte from a return value
// byteIndex: 0=lowest byte, 1=second byte, etc.
// example: ExtractByte(result, 0) gets bits 0 to 7
func ExtractByte(value uintptr, byteIndex int) uint8 {
	return uint8((value >> (byteIndex * 8)) & 0xFF)
}

// ExtractWord extracts a specific 16 bit word from a return value
// wordIndex: 0=low word (bits 0 to 15), 1=high word (bits 16 to 31)
func ExtractWord(value uintptr, wordIndex int) uint16 {
	return uint16((value >> (wordIndex * 16)) & 0xFFFF)
}

// ExtractBits extracts arbitrary bit range from a return value :p
// startBit: starting bit position (0 based from right)
// numBits: number of bits to extract (1 to 32)
// example: ExtractBits(result, 8, 4) gets bits 8 to 11
func ExtractBits(value uintptr, startBit, numBits int) uint32 {
	mask := (uint32(1) << numBits) - 1
	return uint32(value>>startBit) & mask
}

// CombineWords combines two 16 bit words into 32 bit value
func CombineWords(low, high uint16) uint32 {
	return uint32(high)<<16 | uint32(low)
}

// CombineBytes combines four bytes into 32 bit value
func CombineBytes(b0, b1, b2, b3 uint8) uint32 {
	return uint32(b3)<<24 | uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
}

// CombineDwords combines two 32 bit values into 64 bit
func CombineDwords(low, high uint32) uint64 {
	return uint64(high)<<32 | uint64(low)
}

// SplitDwords splits 64 bit value into two 32 bit parts
func SplitDwords(value uint64) (low, high uint32) {
	return uint32(value & 0xFFFFFFFF),
		uint32((value >> 32) & 0xFFFFFFFF)
}

func UTF16ToString(ptr *uint16) string {
	return utils.UTF16ToString(ptr)
}

// ReadUTF16String reads a null terminated utf16 string from a memory pointer :3
// used for apis that return LPWSTR/LPCWSTR pointers like GetCommandLineW
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

// ReadANSIString reads a null terminated ansi string from a memory pointer
// used for apis that return LPSTR/LPCSTR pointers
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

// ReadLARGE_INTEGER reads a 64 bit value from a LARGE_INTEGER structure pointer
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
