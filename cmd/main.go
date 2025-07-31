package main

import (
	"unsafe"
	"github.com/carved4/go-wincall"
	"runtime/debug"
)

func main() {
	// this is needed to prevent gc from collecting our utf16ptrfromstring buffers, fuck you google
	debug.SetGCPercent(-1)
	exampleHighLevel()
	exampleManual()
}

func exampleHighLevel() {
	title, _ := wincall.UTF16ptr("high level api")
	message, _ := wincall.UTF16ptr("twitter.com/owengsmt")
	
	wincall.Call("user32.dll", "MessageBoxW",
		0, // hwnd
		uintptr(unsafe.Pointer(message)),
		uintptr(unsafe.Pointer(title)),
		0, // MB_OK
	)
}

func exampleManual() {
	dllHash := wincall.GetHash("user32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)
	
	funcHash := wincall.GetHash("MessageBoxW")
	funcAddr := wincall.GetFunctionAddress(moduleBase, funcHash)
	
	title, _ := wincall.UTF16ptr("manual")
	message, _ := wincall.UTF16ptr("twitter.com/owengsmt")
	
	wincall.CallInNewThread(
		funcAddr,
		0, // hwnd
		uintptr(unsafe.Pointer(message)),
		uintptr(unsafe.Pointer(title)),
		0, // MB_OK
	)
}

