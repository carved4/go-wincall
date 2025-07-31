package wincall

import (
	"runtime"
	"sync"
	"unsafe"
	"wincall/pkg/obf"
	"wincall/pkg/resolve"
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


func DirectCall(funcAddr uintptr, args ...uintptr) (uintptr, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	
	lc := &libcall{
		fn: funcAddr,
		n:  uintptr(len(args)),
	}
	
	if len(args) > 0 {
		lc.args = uintptr(unsafe.Pointer(&args[0]))
	} else {
		lc.args = 0
	}
	
	wincall(lc)
	
	return lc.r1, nil
}

func initAddresses() {
	kernel32Hash := obf.GetHash("kernel32.dll")
	kernel32Base := resolve.GetModuleBase(kernel32Hash)
	if kernel32Base == 0 {
		return
	}
	loadLibraryWHash := obf.GetHash("LoadLibraryW")
	loadLibraryWAddr = resolve.GetFunctionAddress(kernel32Base, loadLibraryWHash)

	getProcAddressHash := obf.GetHash("GetProcAddress")
	getProcAddressAddr = resolve.GetFunctionAddress(kernel32Base, getProcAddressHash)
}

func LoadLibraryW(name string) uintptr {
	namePtr, _ := UTF16PtrFromString(name)
	r1, _ := DirectCall(getLoadLibraryWAddr(), uintptr(unsafe.Pointer(namePtr)))
	return r1
}

func GetProcAddress(moduleHandle uintptr, proc unsafe.Pointer) uintptr {
	r1, _ := DirectCall(getGetProcAddressAddr(), moduleHandle, uintptr(proc))
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
	r1, _ := DirectCall(isDebuggerPresentAddr)
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

