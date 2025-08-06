package main

import (
	"fmt"
	"unsafe"

	"github.com/carved4/go-wincall"
)

func main() {
	wincall.LoadLibraryW("advapi32.dll")
	wincall.LoadLibraryW("kerberos.dll")
	wincall.LoadLibraryW("combase.dll")
	wincall.LoadLibraryW("shell32.dll")
	wincall.LoadLibraryW("ole32.dll")
	wincall.LoadLibraryW("oleaut32.dll")
	wincall.LoadLibraryW("oleacc.dll")
	wincall.LoadLibraryW("msvcrt.dll")
	wincall.LoadLibraryW("msvcrt.dll")
	exampleHighLevel()
	exampleManual()
}

// high level api usage :3
func exampleHighLevel() {
	commandLinePtr, _ := wincall.Call("kernel32", "GetCommandLineW")
	commandLine := wincall.ReadUTF16String(commandLinePtr)
	fmt.Printf("command line: %s\n", commandLine)

	color, _ := wincall.Call("user32", "GetSysColor", 5)
	r := wincall.ExtractByte(color, 0)
	g := wincall.ExtractByte(color, 1)
	b := wincall.ExtractByte(color, 2)
	fmt.Printf("window color: rgb(%d, %d, %d) = #%02X%02X%02X\n", r, g, b, r, g, b)

	var buffer [260]byte
	length, _ := wincall.Call("kernel32", "GetWindowsDirectoryA", &buffer[0], 260)
	if length > 0 {
		winDir := wincall.ReadANSIString(uintptr(unsafe.Pointer(&buffer[0])))
		fmt.Printf("windows directory: %s\n", winDir)
	}

	var perfCounter int64
	success, _ := wincall.Call("kernel32", "QueryPerformanceCounter", &perfCounter)
	if success != 0 {
		counterValue := wincall.ReadLARGE_INTEGER(uintptr(unsafe.Pointer(&perfCounter)))
		fmt.Printf("performance counter: %d\n", counterValue)
	}

	type RTL_OSVERSIONINFOW struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion      uint32
		dwMinorVersion      uint32
		dwBuildNumber       uint32
		dwPlatformId        uint32
		szCSDVersion        [128]uint16
	}

	var rtlOsvi RTL_OSVERSIONINFOW
	rtlOsvi.dwOSVersionInfoSize = uint32(unsafe.Sizeof(rtlOsvi))

	result, _ := wincall.Call("ntdll", "RtlGetVersion", &rtlOsvi)
	if result == 0 { // NT_SUCCESS
		fmt.Printf("os version: %d.%d.%d\n",
			rtlOsvi.dwMajorVersion, rtlOsvi.dwMinorVersion, rtlOsvi.dwBuildNumber)
	}

	title, _ := wincall.UTF16ptr("high level api")
	message, _ := wincall.UTF16ptr("twitter.com/owengsmt")

	wincall.Call("user32.dll", "MessageBoxW",
		0, // hwnd
		message,
		title,
		0, // MB_OK
	)
}

// manual usage
func exampleManual() {
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
		message,
		title,
		0, // MB_OK
	)
}
