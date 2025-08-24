package wincall

import (
    "runtime"
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

    // Execute the call on g0 (system stack) to satisfy Windows stack probes.
    systemstack(func() {
        wincall(lc)
    })

    // Keep original arguments alive until after the call completes.
    runtime.KeepAlive(args)
    // Zeroize temporary processed arguments to reduce memory forensics residue.
    for i := range processedArgs { processedArgs[i] = 0 }
    return lc.r1, nil
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
func CallG0(funcAddr uintptr, args ...interface{}) (uintptr, error) {
    return DirectCall(funcAddr, args...)
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

        // Add slight jitter to avoid deterministic timing
        jitter := time.Duration((time.Now().UnixNano()>>uint(i%7))%3) * time.Millisecond
        waitTime := time.Duration(10+i*10) * time.Millisecond
        waitTime += jitter
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
            jitter := time.Duration((time.Now().UnixNano()>>uint(i%5))%5) * time.Millisecond
            time.Sleep(time.Duration(10+i*20)*time.Millisecond + jitter)
            continue
        }

        r1, _ := CallG0(loadLibraryAddr, namePtr)
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

func GetProcAddress(moduleHandle uintptr, proc unsafe.Pointer) uintptr {
    r1, _ := CallG0(getGetProcAddressAddr(), moduleHandle, proc)
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
