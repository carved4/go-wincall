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
	LdrLoadDllAddr uintptr
	wincallOnce    sync.Once
)

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

	systemstack(func() {
		wincall(lc)
	})
	runtime.KeepAlive(args)
	for i := range processedArgs {
		processedArgs[i] = 0
	}
	return lc.r1, lc.r2, nil
}

//go:linkname systemstack runtime.systemstack
func systemstack(fn func())

func RunOnG0(fn func()) { systemstack(fn) }

func CurrentThreadIDFast() uint32 { return tidFromTeb() }

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
			LdrLoadDllAddr = resolve.GetFunctionAddress(ntdllBase, LdrLoadDllHash)
			if LdrLoadDllAddr != 0 {
				return
			}
		}
	}
}

func LdrLoadDLL(name string) uintptr {
	unicodeString, utf16Buffer, err := NewUnicodeString(name)
	if err != nil {
		return 0
	}

	var moduleHandle uintptr

	maxRetries := 5

	for i := range maxRetries {
		ldrLoadDllAddr := getLdrLoadDllAddr()
		if ldrLoadDllAddr == 0 {
			break
		}
		r1, _, _ := CallG0(ldrLoadDllAddr,
			uintptr(0),                             // pathtofile (null)
			uintptr(0),                             // flags (0)
			uintptr(unsafe.Pointer(unicodeString)), // modulefilename
			uintptr(unsafe.Pointer(&moduleHandle))) // modulehandle (output)
		if r1 == 0 && moduleHandle != 0 {
			runtime.KeepAlive(utf16Buffer)
			return moduleHandle
		}

		if i < maxRetries-1 {
			jitter := time.Duration((time.Now().UnixNano()>>uint(i%5))%7) * time.Millisecond
			time.Sleep(time.Duration(50+i*50)*time.Millisecond + jitter)
		}
	}

	runtime.KeepAlive(utf16Buffer)
	return 0
}

func LoadDll(name string) uintptr {
	return LdrLoadDLL(name)
}

func getLdrLoadDllAddr() uintptr {
	wincallOnce.Do(initAddresses)
	return LdrLoadDllAddr
}

func IsDebuggerPresent() bool {
	peb := resolve.GetCurrentProcessPEB()
	if peb == nil {
		return false
	}
	return peb.BeingDebugged != 0
}

// UTF16PtrFromString converts a go string to a null terminated utf16 pointer :3
// optimized to avoid rune slice allocation, processes utf8 bytes directly
func UTF16PtrFromString(s string) (*uint16, error) {
	if s == "" {
		// return pointer to single null terminator
		buf := make([]uint16, 1)
		return &buf[0], nil
	}

	// first pass: compute utf16 length
	n := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x80 {
			n++
			i++
			continue
		}
		// decode utf8 manually to avoid utf8.DecodeRuneInString allocation
		var r rune
		var size int
		if c&0xE0 == 0xC0 && i+1 < len(s) {
			r = rune(c&0x1F)<<6 | rune(s[i+1]&0x3F)
			size = 2
		} else if c&0xF0 == 0xE0 && i+2 < len(s) {
			r = rune(c&0x0F)<<12 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F)
			size = 3
		} else if c&0xF8 == 0xF0 && i+3 < len(s) {
			r = rune(c&0x07)<<18 | rune(s[i+1]&0x3F)<<12 | rune(s[i+2]&0x3F)<<6 | rune(s[i+3]&0x3F)
			size = 4
		} else {
			// invalid utf8, skip byte
			n++
			i++
			continue
		}
		if r <= 0xFFFF {
			n++
		} else {
			n += 2 // surrogate pair
		}
		i += size
	}

	// allocate utf16 buffer plus null terminator
	buf := make([]uint16, n+1)

	// second pass: encode
	j := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x80 {
			buf[j] = uint16(c)
			j++
			i++
			continue
		}
		var r rune
		var size int
		if c&0xE0 == 0xC0 && i+1 < len(s) {
			r = rune(c&0x1F)<<6 | rune(s[i+1]&0x3F)
			size = 2
		} else if c&0xF0 == 0xE0 && i+2 < len(s) {
			r = rune(c&0x0F)<<12 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F)
			size = 3
		} else if c&0xF8 == 0xF0 && i+3 < len(s) {
			r = rune(c&0x07)<<18 | rune(s[i+1]&0x3F)<<12 | rune(s[i+2]&0x3F)<<6 | rune(s[i+3]&0x3F)
			size = 4
		} else {
			buf[j] = uint16(c)
			j++
			i++
			continue
		}
		if r <= 0xFFFF {
			buf[j] = uint16(r)
			j++
		} else {
			r -= 0x10000
			buf[j] = 0xD800 + uint16(r>>10)
			buf[j+1] = 0xDC00 + uint16(r&0x3FF)
			j += 2
		}
		i += size
	}

	return &buf[0], nil
}

func BytePtrFromString(s string) (*byte, error) {
	bytes := append([]byte(s), 0)
	return &bytes[0], nil
}

// NewUnicodeString creates a UNICODE_STRING from a go string :p
// optimized to compute byte length without rune slice allocation
func NewUnicodeString(s string) (*utils.UNICODE_STRING, *uint16, error) {
	if s == "" {
		return &utils.UNICODE_STRING{}, nil, nil
	}

	utf16Ptr, err := UTF16PtrFromString(s)
	if err != nil {
		return nil, nil, err
	}

	// compute byte length by processing utf8 directly
	byteLen := uint16(0)
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x80 {
			byteLen += 2
			i++
			continue
		}
		var size int
		var r rune
		if c&0xE0 == 0xC0 && i+1 < len(s) {
			r = rune(c&0x1F)<<6 | rune(s[i+1]&0x3F)
			size = 2
		} else if c&0xF0 == 0xE0 && i+2 < len(s) {
			r = rune(c&0x0F)<<12 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F)
			size = 3
		} else if c&0xF8 == 0xF0 && i+3 < len(s) {
			r = rune(c&0x07)<<18 | rune(s[i+1]&0x3F)<<12 | rune(s[i+2]&0x3F)<<6 | rune(s[i+3]&0x3F)
			size = 4
		} else {
			byteLen += 2
			i++
			continue
		}
		if r <= 0xFFFF {
			byteLen += 2
		} else {
			byteLen += 4 // surrogate pair
		}
		i += size
	}

	us := &utils.UNICODE_STRING{
		Length:        byteLen,
		MaximumLength: byteLen + 2,
		Buffer:        utf16Ptr,
	}

	return us, utf16Ptr, nil
}

var gCallback libcall

var gArgs [16]uintptr

var CallbackEntryPC uintptr

func SetCallbackN(fn uintptr, args ...uintptr) error {
	if len(args) > len(gArgs) {
		return errors.New(errors.Err0)
	}
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

func CallbackPtr() uintptr { return CallbackEntryPC }

func processArg(arg interface{}) uintptr {
	if arg == nil {
		return 0
	}
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
