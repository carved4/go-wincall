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

// API Set structures for dynamic resolution
type API_SET_NAMESPACE struct {
	Version    uint32
	Size       uint32
	Flags      uint32
	Count      uint32
	EntryOffset uint32
	HashOffset uint32
	HashFactor uint32
}

type API_SET_NAMESPACE_ENTRY struct {
	Flags       uint32
	NameOffset  uint32
	NameLength  uint32
	HashedLength uint32
	ValueOffset uint32
	ValueCount  uint32
}

type API_SET_VALUE_ENTRY struct {
	Flags       uint32
	NameOffset  uint32
	NameLength  uint32
	ValueOffset uint32
	ValueLength uint32
}

var (
	moduleCache       = make(map[uint32][]byte)
	moduleCacheMutex  sync.RWMutex
	functionCache     = make(map[string][]byte)
	functionCacheMutex sync.RWMutex
	syscallCache      = make(map[uint32]uint16)
	syscallCacheMutex sync.RWMutex
	sortedExports     []pe.Export
	sortedExportsOnce sync.Once
	
	loadLibraryCallback func(string) uintptr
)

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
	
	if functionHash < 65536 {
		for _, export := range exports {
			if export.Ordinal == uint32(functionHash) {
				foundExport = &export
				break
			}
		}
	}
	
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

func resolveApiSet(dllName string) string {
	// If it's not an API Set DLL, return as-is
	if !strings.HasPrefix(strings.ToLower(dllName), "api-ms-") {
		return dllName
	}

	peb := GetCurrentProcessPEB()
	if peb == nil || peb.ApiSetMap == 0 {
		return dllName
	}

	apiSetMap := (*API_SET_NAMESPACE)(unsafe.Pointer(peb.ApiSetMap))
	if apiSetMap == nil || apiSetMap.Count == 0 {
		return dllName
	}

	// Convert DLL name to UTF-16 for comparison (removing .dll extension)
	searchName := strings.ToLower(dllName)
	if strings.HasSuffix(searchName, ".dll") {
		searchName = searchName[:len(searchName)-4]
	}

	// Get the first entry
	entryPtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(apiSetMap.EntryOffset)
	
	for i := uint32(0); i < apiSetMap.Count; i++ {
		entry := (*API_SET_NAMESPACE_ENTRY)(unsafe.Pointer(entryPtr + uintptr(i)*unsafe.Sizeof(API_SET_NAMESPACE_ENTRY{})))
		
		// Read the API Set name
		namePtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(entry.NameOffset)
		nameBytes := (*[256]uint16)(unsafe.Pointer(namePtr))
		nameLen := entry.NameLength / 2 // Convert from bytes to UTF-16 chars
		
		if nameLen > 256 {
			continue
		}
		
		// Convert to string
		nameSlice := make([]uint16, nameLen)
		for j := uint32(0); j < nameLen; j++ {
			nameSlice[j] = nameBytes[j]
		}
		apiSetName := strings.ToLower(utils.UTF16ToString(&nameSlice[0]))
		
		// Check if this matches our search
		if strings.ToLower(apiSetName) == searchName {
			// Found match, get the value (real DLL name)
			if entry.ValueCount == 0 {
				continue
			}
			
			valuePtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(entry.ValueOffset)
			value := (*API_SET_VALUE_ENTRY)(unsafe.Pointer(valuePtr))
			
			// Read the real DLL name
			realDllPtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(value.ValueOffset)
			realDllBytes := (*[256]uint16)(unsafe.Pointer(realDllPtr))
			realDllLen := value.ValueLength / 2
			
			if realDllLen > 256 {
				continue
			}
			
			realDllSlice := make([]uint16, realDllLen)
			for j := uint32(0); j < realDllLen; j++ {
				realDllSlice[j] = realDllBytes[j]
			}
			realDllName := utils.UTF16ToString(&realDllSlice[0])
			
			// Add .dll extension if not present
			if !strings.HasSuffix(strings.ToLower(realDllName), ".dll") {
				realDllName += ".dll"
			}
			
			return realDllName
		}
	}

	// If not found, try to find a similar API Set with a different version
	// Extract the base name (without version) for fallback matching
	// e.g., "api-ms-win-core-com-l1-1-0" -> "api-ms-win-core-com"
 // This should work in almost all cases, and it rarely happens regardless. 
	baseName := searchName
	if idx := strings.LastIndex(searchName, "-l"); idx != -1 {
		baseName = searchName[:idx]
	}
	
	var fallbackDLL string
	for i := uint32(0); i < apiSetMap.Count; i++ {
		entry := (*API_SET_NAMESPACE_ENTRY)(unsafe.Pointer(entryPtr + uintptr(i)*unsafe.Sizeof(API_SET_NAMESPACE_ENTRY{})))
		
		// Read the API Set name
		namePtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(entry.NameOffset)
		nameBytes := (*[256]uint16)(unsafe.Pointer(namePtr))
		nameLen := entry.NameLength / 2
		
		if nameLen > 0 && nameLen < 100 {
			nameSlice := make([]uint16, nameLen)
			for j := uint32(0); j < nameLen; j++ {
				nameSlice[j] = nameBytes[j]
			}
			apiSetName := strings.ToLower(utils.UTF16ToString(&nameSlice[0]))
			
			// Check if this is a version variant of our target
			if strings.HasPrefix(apiSetName, baseName+"-l") {
				
				// Get the value (real DLL name) for this alternative
				if entry.ValueCount > 0 {
					valuePtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(entry.ValueOffset)
					value := (*API_SET_VALUE_ENTRY)(unsafe.Pointer(valuePtr))
					
					// Read the real DLL name
					realDllPtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(value.ValueOffset)
					realDllBytes := (*[256]uint16)(unsafe.Pointer(realDllPtr))
					realDllLen := value.ValueLength / 2
					
					if realDllLen > 0 && realDllLen < 256 {
						realDllSlice := make([]uint16, realDllLen)
						for k := uint32(0); k < realDllLen; k++ {
							realDllSlice[k] = realDllBytes[k]
						}
						fallbackDLL = utils.UTF16ToString(&realDllSlice[0])
						
						// Add .dll extension if not present
						if !strings.HasSuffix(strings.ToLower(fallbackDLL), ".dll") {
							fallbackDLL += ".dll"
						}
						
						return fallbackDLL
					}
				}
			}
		}
	}

	// If no fallback found, return original name
	return dllName
}

func isForwardedExport(moduleBase, funcAddr uintptr, file *pe.File) bool {
	if file.OptionalHeader == nil {
		return false
	}
	
	rva := uint32(funcAddr - moduleBase)
	
	if oh64, ok := file.OptionalHeader.(*pe.OptionalHeader64); ok {
		exportDir := oh64.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		return rva >= exportDir.VirtualAddress && rva < exportDir.VirtualAddress+exportDir.Size
	} else if oh32, ok := file.OptionalHeader.(*pe.OptionalHeader32); ok {
		exportDir := oh32.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		return rva >= exportDir.VirtualAddress && rva < exportDir.VirtualAddress+exportDir.Size
	}
	
	return false
}

func getForwarderString(funcAddr uintptr) string {
	ptr := (*byte)(unsafe.Pointer(funcAddr))
	var result []byte
	
	for i := 0; i < 256; i++ { 
		if *ptr == 0 {
			break
		}
		result = append(result, *ptr)
		ptr = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1))
	}
	
	return string(result)
}

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

	// Handle API Set DLLs - resolve them to their actual implementation
	actualDLL := resolveApiSet(targetDLL)
	
	dllHash := obf.GetHash(actualDLL)
	moduleBase := GetModuleBase(dllHash)

	if moduleBase == 0 && loadLibraryCallback != nil {
		loadLibraryCallback(actualDLL)
		moduleBase = GetModuleBase(dllHash)
	}
	
	if moduleBase == 0 {
		return 0
	}

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