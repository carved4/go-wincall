package wincall

import (
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/errors"
	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/resolve"
	"github.com/carved4/go-wincall/pkg/utils"
)

var (
	LdrLoadDllAddr   uintptr
	loadLibraryWAddr uintptr
	wincallOnce      sync.Once
)

var SyscallDirectEntryPC uintptr

//go:noescape
func wincall(libcall *libcall)

//go:noescape
func tidFromTeb() uint32

type libcall struct {
	fn   uintptr
	n    uintptr
	args uintptr
	r1   uintptr
	r2   uintptr
	err  uintptr
}

func DirectCall(funcAddr uintptr, args ...any) (uintptr, uintptr, error) {
	processedArgs := make([]uintptr, len(args))
	for i, arg := range args {
		processedArgs[i] = processArg(arg)
	}

	lc := &libcall{
		fn: funcAddr,
		n:  uintptr(len(processedArgs)),
	}

	if len(processedArgs) > 0 {
		lc.args = uintptr(unsafe.Pointer(&processedArgs[0]))
	} else {
		lc.args = 0
	}

	// Execute the call on g0 (system stack) to satisfy Windows stack probes.
	systemstack(func() {
		wincall(lc)
	})

	// Keep original arguments alive until after the call completes.
	runtime.KeepAlive(args)
	// Zeroize temporary processed arguments to reduce memory forensics residue.
	for i := range processedArgs {
		processedArgs[i] = 0
	}
	return lc.r1, lc.r2, nil
}

//go:linkname systemstack runtime.systemstack
func systemstack(fn func())

// RunOnG0 runs the provided closure on the Go system stack (g0).
func RunOnG0(fn func()) { systemstack(fn) }

// CurrentThreadIDFast reads the TID from the TEB. Safe on g0.
func CurrentThreadIDFast() uint32 { return tidFromTeb() }

// CallG0 invokes the target function using the Go system stack (g0)
// instead of a dedicated native thread. This avoids needing a persistent
// worker and ensures compatibility with _chkstk and large stack probes.
func CallG0(funcAddr uintptr, args ...any) (uintptr, uintptr, error) {
	return DirectCall(funcAddr, args...)
}

func initAddresses() {
	maxRetries := 10

	for i := 0; i < maxRetries; i++ {
		ntdllHash := obf.GetHash("ntdll.dll")
		ntdllBase := resolve.GetModuleBase(ntdllHash)
		kernel32Hash := obf.GetHash("kernel32.dll")
		kernel32Base := resolve.GetModuleBase(kernel32Hash)
		LdrLoadDllHash := obf.GetHash("LdrLoadDLL")
		if kernel32Base != 0 && ntdllBase != 0 {
			loadLibraryWHash := obf.GetHash("LoadLibraryW")
			loadLibraryWAddr = resolve.GetFunctionAddress(kernel32Base, loadLibraryWHash)
			LdrLoadDllAddr = resolve.GetFunctionAddress(ntdllBase, LdrLoadDllHash)
			if loadLibraryWAddr != 0 && LdrLoadDllAddr != 0 {
				return
			}
		}
	}
}

func LoadLibraryW(name string) uintptr {
	namePtr, _ := UTF16PtrFromString(name)

	maxRetries := 5

	for i := range maxRetries {
		loadLibraryAddr := getLoadLibraryWAddr()
		if loadLibraryAddr == 0 {
			break
		}

		r1, _, _ := CallG0(loadLibraryAddr, namePtr)
		if r1 != 0 {
			return r1
		}

		if i < maxRetries-1 {
			jitter := time.Duration((time.Now().UnixNano()>>uint(i%5))%7) * time.Millisecond
			time.Sleep(time.Duration(50+i*50)*time.Millisecond + jitter)
		}
	}
	// we should never get here
	return 0
}

/*
LdrLoadDll(

	IN PWCHAR               PathToFile OPTIONAL,
	IN ULONG                Flags OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle );
*/
func LdrLoadDLL(name string) uintptr {
	// Create UNICODE_STRING for the module name
	unicodeString, utf16Buffer, err := NewUnicodeString(name)
	if err != nil {
		return 0
	}

	// Storage for the module handle (output parameter)
	var moduleHandle uintptr

	maxRetries := 5

	for i := range maxRetries {
		ldrLoadDllAddr := getLdrLoadDllAddr()
		if ldrLoadDllAddr == 0 {
			break
		}

		// Call LdrLoadDll with:
		// PathToFile = NULL (let system find the DLL)
		// Flags = 0 (default flags)
		// ModuleFileName = our UNICODE_STRING
		// ModuleHandle = pointer to our output variable
		r1, _, _ := CallG0(ldrLoadDllAddr,
			uintptr(0),                             // PathToFile (NULL)
			uintptr(0),                             // Flags (0)
			uintptr(unsafe.Pointer(unicodeString)), // ModuleFileName
			uintptr(unsafe.Pointer(&moduleHandle))) // ModuleHandle (output)

		// NTSTATUS success codes are typically 0 or positive
		// Error codes are negative (0x80000000+)
		if r1 == 0 && moduleHandle != 0 {
			// Keep the UTF-16 buffer alive until after the call
			runtime.KeepAlive(utf16Buffer)
			return moduleHandle
		}

		if i < maxRetries-1 {
			jitter := time.Duration((time.Now().UnixNano()>>uint(i%5))%7) * time.Millisecond
			time.Sleep(time.Duration(50+i*50)*time.Millisecond + jitter)
		}
	}

	// Keep the UTF-16 buffer alive until cleanup
	runtime.KeepAlive(utf16Buffer)
	return 0
}

// LoadLibraryLdr is an alternative to LoadLibraryW using LdrLoadDll from ntdll
// This provides a lower-level interface that bypasses some kernel32 hooks
func LoadLibraryLdr(name string) uintptr {
	return LdrLoadDLL(name)
}

func getLdrLoadDllAddr() uintptr {
	wincallOnce.Do(initAddresses)
	return LdrLoadDllAddr
}

func getLoadLibraryWAddr() uintptr {
	wincallOnce.Do(initAddresses)
	return loadLibraryWAddr
}

func IsDebuggerPresent() bool {
	// Use PEB.BeingDebugged to avoid importing or resolving the API name
	peb := resolve.GetCurrentProcessPEB()
	if peb == nil {
		return false
	}
	return peb.BeingDebugged != 0
}

func UTF16PtrFromString(s string) (*uint16, error) {
	runes := []rune(s)
	buf := make([]uint16, len(runes)+1)
	for i, r := range runes {
		if r <= 0xFFFF {
			buf[i] = uint16(r)
		} else {
			r -= 0x10000
			buf[i] = 0xD800 + uint16(r>>10)
			i++
			buf[i] = 0xDC00 + uint16(r&0x3FF)
		}
	}
	return &buf[0], nil
}

func BytePtrFromString(s string) (*byte, error) {
	bytes := append([]byte(s), 0)
	return &bytes[0], nil
}

// NewUnicodeString creates a UNICODE_STRING from a Go string
func NewUnicodeString(s string) (*utils.UNICODE_STRING, *uint16, error) {
	if s == "" {
		return &utils.UNICODE_STRING{}, nil, nil
	}

	utf16Ptr, err := UTF16PtrFromString(s)
	if err != nil {
		return nil, nil, err
	}

	// Calculate length in bytes (UTF-16 characters * 2)
	runes := []rune(s)
	byteLen := uint16(0)
	for _, r := range runes {
		if r <= 0xFFFF {
			byteLen += 2
		} else {
			byteLen += 4 // Surrogate pair
		}
	}

	us := &utils.UNICODE_STRING{
		Length:        byteLen,
		MaximumLength: byteLen + 2, // Add space for null terminator
		Buffer:        utf16Ptr,
	}

	return us, utf16Ptr, nil
}

// gCallback holds the libcall block used by the foreign-callable entry.
// External code will call into CallbackEntry, which loads the address
// of this struct into CX and jumps to wincall_asmstdcall.
var gCallback libcall

// Backing storage for up to 16 uintptr args to match the asm limit.
var gArgs [16]uintptr

// SetCallbackN configures the callback target and its arguments.
// Up to 16 arguments are supported; additional args will return an error.
func SetCallbackN(fn uintptr, args ...uintptr) error {
	if len(args) > len(gArgs) {
		return errors.New(errors.Err0)
	}
	// Copy args into static storage
	for i := range args {
		gArgs[i] = args[i]
	}
	gCallback.fn = fn
	gCallback.n = uintptr(len(args))
	if len(args) > 0 {
		gCallback.args = uintptr(unsafe.Pointer(&gArgs[0]))
	} else {
		gCallback.args = 0
	}
	return nil
}

// Populated by assembly with the address of CallbackEntry.
var CallbackEntryPC uintptr

// CallbackPtr returns the raw code pointer to CallbackEntry.
func CallbackPtr() uintptr { return CallbackEntryPC }

func processArg(arg interface{}) uintptr {
	if arg == nil {
		return 0
	}
	// To avoid reflection, we handle common types explicitly.
	switch v := arg.(type) {
	case uintptr:
		return v
	case unsafe.Pointer:
		return uintptr(v)
	case *byte:
		return uintptr(unsafe.Pointer(v))
	case *uint16:
		return uintptr(unsafe.Pointer(v))
	case *uint32:
		return uintptr(unsafe.Pointer(v))
	case *uint64:
		return uintptr(unsafe.Pointer(v))
	case *int8:
		return uintptr(unsafe.Pointer(v))
	case *int16:
		return uintptr(unsafe.Pointer(v))
	case *int32:
		return uintptr(unsafe.Pointer(v))
	case *int64:
		return uintptr(unsafe.Pointer(v))
	case *int:
		return uintptr(unsafe.Pointer(v))
	case *uint:
		return uintptr(unsafe.Pointer(v))
	case *uintptr:
		return uintptr(unsafe.Pointer(v))
	case *struct{}:
		return uintptr(unsafe.Pointer(v))
	case *[0]byte:
		return uintptr(unsafe.Pointer(v))
	case int:
		return uintptr(v)
	case int8:
		return uintptr(int64(v))
	case int16:
		return uintptr(int64(v))
	case int32:
		return uintptr(int64(v))
	case int64:
		return uintptr(v)
	case uint:
		return uintptr(v)
	case uint8:
		return uintptr(uint64(v))
	case uint16:
		return uintptr(uint64(v))
	case uint32:
		return uintptr(uint64(v))
	case uint64:
		return uintptr(v)
	case bool:
		if v {
			return 1
		}
		return 0
	}
	panic(errors.New(errors.Err1))
}
