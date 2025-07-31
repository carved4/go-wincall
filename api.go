package wincall

import (
	"wincall/pkg/obf"
	"wincall/pkg/resolve"
	"wincall/pkg/wincall"
)


var CallInNewThread = wincall.CallInNewThread
var LoadLibraryW = wincall.LoadLibraryW
var GetProcAddress = wincall.GetProcAddress
func UTF16PtrFromString(s string) (*uint16, error) {
	return wincall.UTF16PtrFromString(s)
}
var GetModuleBase = resolve.GetModuleBase
var GetFunctionAddress = resolve.GetFunctionAddress
var GetHash = obf.DBJ2HashStr
func Call(dllName, funcName string, args ...uintptr) (uintptr, error) {
	dllHash := obf.GetHash(dllName)
	moduleBase := resolve.GetModuleBase(dllHash)
	if moduleBase == 0 {
		moduleBase = wincall.LoadLibraryW(dllName)
		if moduleBase == 0 {
			return 0, nil
		}
	}
	funcHash := obf.GetHash(funcName)
	funcAddr := resolve.GetFunctionAddress(moduleBase, funcHash)
	if funcAddr == 0 {
		return 0, nil
	}
	return wincall.CallInNewThread(funcAddr, args...)
}

func UTF16ptr(s string) (*uint16, error){
	ptr, err := wincall.UTF16PtrFromString(s)
	return ptr, err
}
