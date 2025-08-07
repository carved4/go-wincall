package wincall

import (
	"sync"
	"time"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/resolve"
)

var (
	loadLibraryWAddr   uintptr
	getProcAddressAddr uintptr
	wincallOnce        sync.Once
)

//go:noescape
func wincall(libcall *libcall)

type libcall struct {
	fn   uintptr
	n    uintptr
	args uintptr
	r1   uintptr
	r2   uintptr
	err  uintptr
}

func DirectCall(funcAddr uintptr, args ...interface{}) (uintptr, error) {
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

	wincall(lc)

	return lc.r1, nil
}

func initAddresses() {
	maxRetries := 10

	for i := 0; i < maxRetries; i++ {
		kernel32Hash := obf.GetHash("kernel32.dll")
		kernel32Base := resolve.GetModuleBase(kernel32Hash)

		if kernel32Base != 0 {
			loadLibraryWHash := obf.GetHash("LoadLibraryW")
			loadLibraryWAddr = resolve.GetFunctionAddress(kernel32Base, loadLibraryWHash)

			getProcAddressHash := obf.GetHash("GetProcAddress")
			getProcAddressAddr = resolve.GetFunctionAddress(kernel32Base, getProcAddressHash)

			if loadLibraryWAddr != 0 && getProcAddressAddr != 0 {
				return
			}
		}

		waitTime := time.Duration(10+i*10) * time.Millisecond
		if waitTime > 100*time.Millisecond {
			waitTime = 100 * time.Millisecond
		}
		time.Sleep(waitTime)
	}
}

func LoadLibraryW(name string) uintptr {
	namePtr, _ := UTF16PtrFromString(name)

	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		loadLibraryAddr := getLoadLibraryWAddr()
		if loadLibraryAddr == 0 {
			time.Sleep(time.Duration(10+i*20) * time.Millisecond)
			continue
		}

		r1, err := CallWorker(loadLibraryAddr, namePtr)

		if err == nil && r1 != 0 {
			return r1
		}

		if i < maxRetries-1 {
			time.Sleep(time.Duration(50+i*50) * time.Millisecond)
		}
	}
	// we should never get here
	return 0
}

func GetProcAddress(moduleHandle uintptr, proc unsafe.Pointer) uintptr {
	r1, _ := CallWorker(getGetProcAddressAddr(), moduleHandle, proc)
	return r1
}

func getLoadLibraryWAddr() uintptr {
	wincallOnce.Do(initAddresses)
	return loadLibraryWAddr
}

func getGetProcAddressAddr() uintptr {
	wincallOnce.Do(initAddresses)
	return getProcAddressAddr
}

func IsDebuggerPresent() bool {
	kernel32Hash := obf.GetHash("kernel32.dll")
	kernel32Base := resolve.GetModuleBase(kernel32Hash)
	procName, _ := BytePtrFromString("IsDebuggerPresent")
	isDebuggerPresentAddr := GetProcAddress(kernel32Base, unsafe.Pointer(procName))
	if isDebuggerPresentAddr == 0 {
		return false
	}
	r1, _ := CallWorker(isDebuggerPresentAddr)
	return r1 != 0
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