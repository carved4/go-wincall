package resolve

import (
	"fmt"
	"strings"
	"strconv"
	"sync"
	"time"
	"unsafe"
	"github.com/carved4/go-wincall/pkg/utils"
	"github.com/Binject/debug/pe"
	"github.com/carved4/go-wincall/pkg/obf"
)

var (
	moduleCache       = make(map[uint32][]byte)
	moduleCacheMutex  sync.RWMutex
	functionCache     = make(map[string][]byte)
	functionCacheMutex sync.RWMutex
	syscallCache      = make(map[uint32]uint16)
	syscallCacheMutex sync.RWMutex
	sortedExports     []pe.Export
	sortedExportsOnce sync.Once
	
	// Callback to load libraries - set by higher level packages to avoid circular imports
	loadLibraryCallback func(string) uintptr
)

// SetLoadLibraryCallback sets the callback function for loading libraries
// This avoids circular dependencies between resolve and wincall packages
func SetLoadLibraryCallback(callback func(string) uintptr) {
	loadLibraryCallback = callback
}

//go:nosplit
//go:noinline
func GetPEB() uintptr

func GetCurrentProcessPEB() *utils.PEB {
	pebAddr := GetPEB()
	if pebAddr == 0 {
		return nil
	}

	maxRetries := 5
	var peb *utils.PEB

	for i := 0; i < maxRetries; i++ {
		peb = (*utils.PEB)(unsafe.Pointer(pebAddr))

		if peb != nil && peb.Ldr != nil {
			return peb
		}

		time.Sleep(100 * time.Millisecond)
	}

	return peb
}

func GetModuleBase(moduleHash uint32) uintptr {
	moduleCacheMutex.RLock()
	if encodedBase, ok := moduleCache[moduleHash]; ok {
		moduleCacheMutex.RUnlock()
		return obf.DecodeUintptr(encodedBase)
	}
	moduleCacheMutex.RUnlock()

	maxRetries := 5
	var moduleBase uintptr

	for i := 0; i < maxRetries; i++ {
		peb := GetCurrentProcessPEB()
		if peb == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if peb.Ldr == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		entry := &peb.Ldr.InLoadOrderModuleList
		currentEntry := entry.Flink

		if currentEntry == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		for currentEntry != entry {
			dataTableEntry := (*utils.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(currentEntry))

			baseName := utils.UTF16ToString(dataTableEntry.BaseDllName.Buffer)

			currentHash := obf.GetHash(baseName)

			if currentHash == moduleHash {
				moduleBase = dataTableEntry.DllBase
				break
			}

			currentEntry = currentEntry.Flink

			if currentEntry == nil {
				break
			}
		}

		if moduleBase != 0 {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	if moduleBase != 0 {
		encodedBase := obf.EncodeUintptr(moduleBase)
		moduleCacheMutex.Lock()
		moduleCache[moduleHash] = encodedBase
		moduleCacheMutex.Unlock()
	}

	return moduleBase
}

func GetFunctionAddress(moduleBase uintptr, functionHash uint32) uintptr {
	cacheKey := fmt.Sprintf("%d-%d", moduleBase, functionHash)
	functionCacheMutex.RLock()
	if encodedAddr, ok := functionCache[cacheKey]; ok {
		functionCacheMutex.RUnlock()
		return obf.DecodeUintptr(encodedAddr)
	}
	functionCacheMutex.RUnlock()

	if moduleBase == 0 {
		return 0
	}

	dosHeader := (*[64]byte)(unsafe.Pointer(moduleBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return 0
	}

	peOffset := *(*uint32)(unsafe.Pointer(moduleBase + 60))
	if peOffset >= 1024 {
		return 0
	}

	peHeader := (*[1024]byte)(unsafe.Pointer(moduleBase + uintptr(peOffset)))
	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		return 0
	}

	sizeOfImage := *(*uint32)(unsafe.Pointer(moduleBase + uintptr(peOffset) + 24 + 56))

	dataSlice := unsafe.Slice((*byte)(unsafe.Pointer(moduleBase)), sizeOfImage)

	file, err := pe.NewFileFromMemory(&memoryReaderAt{data: dataSlice})
	if err != nil {
		return 0
	}
	defer file.Close()

	exports, err := file.Exports()
	if err != nil {
		return 0
	}

	var funcAddr uintptr
	var foundExport *pe.Export
	
	// Check if functionHash represents an ordinal (small integer < 65536)
	// Ordinals are typically small numbers, so we use this heuristic
	if functionHash < 65536 {
		// Try to find by ordinal first
		for _, export := range exports {
			if export.Ordinal == uint32(functionHash) {
				foundExport = &export
				break
			}
		}
	}
	
	// If not found by ordinal or functionHash >= 65536, try by name hash
	if foundExport == nil {
		for _, export := range exports {
			if export.Name != "" {
				currentHash := obf.GetHash(export.Name)
				if currentHash == functionHash {
					foundExport = &export
					break
				}
			}
		}
	}
	
	if foundExport != nil {
		funcAddr = moduleBase + uintptr(foundExport.VirtualAddress)
		
		// Check if this is a forwarded export using pe library
		if isForwardedExport(moduleBase, funcAddr, file) {
			forwarderString := getForwarderString(funcAddr)
			if resolvedAddr := resolveForwardedExport(forwarderString); resolvedAddr != 0 {
				funcAddr = resolvedAddr
			}
		}
	}

	if funcAddr != 0 {
		encodedAddr := obf.EncodeUintptr(funcAddr)
		functionCacheMutex.Lock()
		functionCache[cacheKey] = encodedAddr
		functionCacheMutex.Unlock()
	}

	return funcAddr
}

// isForwardedExport checks if an export is forwarded by checking if the RVA points to the export section
func isForwardedExport(moduleBase, funcAddr uintptr, file *pe.File) bool {
	if file.OptionalHeader == nil {
		return false
	}
	
	rva := uint32(funcAddr - moduleBase)
	
	// Check export directory from data directories
	if oh64, ok := file.OptionalHeader.(*pe.OptionalHeader64); ok {
		exportDir := oh64.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		return rva >= exportDir.VirtualAddress && rva < exportDir.VirtualAddress+exportDir.Size
	} else if oh32, ok := file.OptionalHeader.(*pe.OptionalHeader32); ok {
		exportDir := oh32.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		return rva >= exportDir.VirtualAddress && rva < exportDir.VirtualAddress+exportDir.Size
	}
	
	return false
}

// getForwarderString reads the forwarder string from the export address
func getForwarderString(funcAddr uintptr) string {
	ptr := (*byte)(unsafe.Pointer(funcAddr))
	var result []byte
	
	for i := 0; i < 256; i++ { // Safety limit
		if *ptr == 0 {
			break
		}
		result = append(result, *ptr)
		ptr = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1))
	}
	
	return string(result)
}

// resolveForwardedExport resolves a forwarded export to its actual address
func resolveForwardedExport(forwarderString string) uintptr {
	parts := strings.Split(forwarderString, ".")
	if len(parts) != 2 {
		return 0
	}

	targetDLL := parts[0]
	targetFunction := parts[1]

	if !strings.HasSuffix(strings.ToLower(targetDLL), ".dll") {
		targetDLL += ".dll"
	}
	
	// First, try to get the module base in case it's already loaded
	dllHash := obf.GetHash(targetDLL)
	moduleBase := GetModuleBase(dllHash)
	
	// If not loaded and we have a callback, try to load it
	if moduleBase == 0 && loadLibraryCallback != nil {
		loadLibraryCallback(targetDLL)
		// Retry getting the module base after loading
		moduleBase = GetModuleBase(dllHash)
	}
	
	if moduleBase == 0 {
		return 0
	}

	// Handle ordinal vs name
	if strings.HasPrefix(targetFunction, "#") {
		ordinalStr := targetFunction[1:]
		ordinal, err := strconv.ParseUint(ordinalStr, 10, 32)
		if err != nil {
			return 0
		}
		return GetFunctionAddress(moduleBase, uint32(ordinal))
	} else {
		funcHash := obf.GetHash(targetFunction)
		return GetFunctionAddress(moduleBase, funcHash)
	}
}