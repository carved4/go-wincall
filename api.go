package wincall

import (
	"fmt"
	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/resolve"
	"github.com/carved4/go-wincall/pkg/wincall"
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
	dllHash := GetHash(dllName) 
	moduleBase := GetModuleBase(dllHash)
	if moduleBase == 0 {
		moduleBase = wincall.LoadLibraryW(dllName)
		if moduleBase == 0 {
			return 0, fmt.Errorf("failed to load DLL: %s", dllName)
		}
	}
	funcHash := GetHash(funcName) 
	funcAddr := GetFunctionAddress(moduleBase, funcHash)
	if funcAddr == 0 {
		return 0, fmt.Errorf("failed to resolve function: %s in %s", funcName, dllName)
	}
	
	// Explicitly capture result to ensure proper return value propagation
	// This prevents compiler optimization issues that can cause return value loss
	result, err := wincall.CallInNewThread(funcAddr, args...)
	if err != nil {
		return 0, err
	}
	return result, nil
}

func UTF16ptr(s string) (*uint16, error){
	ptr, err := wincall.UTF16PtrFromString(s)
	return ptr, err
}
