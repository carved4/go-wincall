package main

import (
	"fmt"
	"unsafe"
	"github.com/carved4/go-wincall"
	"runtime/debug"
	"runtime"
)

func main() {
	runtime.GC()
	runtime.GC()
	// this is needed to prevent gc from collecting our utf16ptrfromstring buffers, fuck you google
	debug.SetGCPercent(-1)
	// example of loading arbitrary dlls
	wincall.LoadLibraryW("advapi32.dll")
	wincall.LoadLibraryW("ole32.dll")
	wincall.LoadLibraryW("kerberos.dll")
	wincall.LoadLibraryW("msvcrt.dll")
	exampleHighLevel()
	exampleManual()	
}
// high level api usage :3
func exampleHighLevel() {
	commandLinePtr, _ := wincall.Call("kernel32", "GetCommandLineW")
	// use utility function to read utf16 back to go string
	commandLine := wincall.ReadUTF16String(commandLinePtr)
	fmt.Printf("Command line: %s\n", commandLine)
	// get system window background color (COLOR_WINDOW = 5)
	color, _ := wincall.Call("user32", "GetSysColor", 5)

	// decode RGB components from the packed color value
	r := wincall.ExtractByte(color, 0)
	g := wincall.ExtractByte(color, 1)    
	b := wincall.ExtractByte(color, 2)  

	fmt.Printf("window color: rgb(%d, %d, %d) = #%02X%02X%02X\n", r, g, b, r, g, b)
	
	// use utility function to read ANSI string - GetWindowsDirectoryA returns ANSI string
	var buffer [260]byte // MAX_PATH buffer
	length, _ := wincall.Call("kernel32", "GetWindowsDirectoryA", 
		uintptr(unsafe.Pointer(&buffer[0])), 260)
	if length > 0 {
		winDir := wincall.ReadANSIString(uintptr(unsafe.Pointer(&buffer[0])))
		fmt.Printf("Windows directory: %s\n", winDir)
	}
	
	// use utility function to read LARGE_INTEGER - QueryPerformanceCounter
	var perfCounter int64
	success, _ := wincall.Call("kernel32", "QueryPerformanceCounter", 
		uintptr(unsafe.Pointer(&perfCounter)))
	if success != 0 {
		// the value is written directly to our variable, but demonstrate reading from pointer
		counterValue := wincall.ReadLARGE_INTEGER(uintptr(unsafe.Pointer(&perfCounter)))
		fmt.Printf("Performance counter: %d\n", counterValue)
	}
	type RTL_OSVERSIONINFOW struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion     uint32
		dwMinorVersion     uint32
		dwBuildNumber      uint32
		dwPlatformId       uint32
		szCSDVersion       [128]uint16
	}

	var rtlOsvi RTL_OSVERSIONINFOW
	rtlOsvi.dwOSVersionInfoSize = uint32(unsafe.Sizeof(rtlOsvi))

	result, _ := wincall.Call("ntdll", "RtlGetVersion", 
		uintptr(unsafe.Pointer(&rtlOsvi)))
	if result == 0 { // NT_SUCCESS
		fmt.Printf("OS Version: %d.%d.%d\n", 
			rtlOsvi.dwMajorVersion, rtlOsvi.dwMinorVersion, rtlOsvi.dwBuildNumber)
	}
	
	title, _ := wincall.UTF16ptr("high level api")
	message, _ := wincall.UTF16ptr("twitter.com/owengsmt")
	
	wincall.Call("user32.dll", "MessageBoxW",
		0, // hwnd
		uintptr(unsafe.Pointer(message)),
		uintptr(unsafe.Pointer(title)),
		0, // MB_OK
	)
}
// manual usage
func exampleManual() {
	// load explicitly so its in our PEB LDR for GetModuleBase() to succeed :3
	wincall.LoadLibraryW("user32.dll")
	dllHash := wincall.GetHash("user32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)
	
	funcHash := wincall.GetHash("MessageBoxW")
	funcAddr := wincall.GetFunctionAddress(moduleBase, funcHash)
	
	title, _ := wincall.UTF16ptr("manual")
	message, _ := wincall.UTF16ptr("twitter.com/owengsmt")
	
	wincall.CallWorker(
		funcAddr,
		0, // hwnd
		uintptr(unsafe.Pointer(message)),
		uintptr(unsafe.Pointer(title)),
		0, // MB_OK
	)
}
