package resolve

import (
	"fmt"
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
)

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
	
	// Check if functionHash represents an ordinal (small integer < 65536)
	// Ordinals are typically small numbers, so we use this heuristic
	if functionHash < 65536 {
		// Try to find by ordinal first
		for _, export := range exports {
			if export.Ordinal == uint32(functionHash) {
				funcAddr = moduleBase + uintptr(export.VirtualAddress)
				break
			}
		}
	}
	
	// If not found by ordinal or functionHash >= 65536, try by name hash
	if funcAddr == 0 {
		for _, export := range exports {
			if export.Name != "" {
				currentHash := obf.GetHash(export.Name)
				if currentHash == functionHash {
					funcAddr = moduleBase + uintptr(export.VirtualAddress)
					break
				}
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
