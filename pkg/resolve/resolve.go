package resolve

import (
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/utils"
)

// Export represents a single exported symbol from a PE image
type Export struct {
	Name           string
	VirtualAddress uint32
	Ordinal        uint32
}

// getExportDirectoryRange reads the Export Data Directory (RVA, Size)
func getExportDirectoryRange(moduleBase uintptr) (uint32, uint32) {
	if moduleBase == 0 {
		return 0, 0
	}

	// Verify DOS header
	dos := (*[64]byte)(unsafe.Pointer(moduleBase))
	if dos[0] != 'M' || dos[1] != 'Z' {
		return 0, 0
	}

	peOff := *(*uint32)(unsafe.Pointer(moduleBase + 0x3C))
	nt := (*[256]byte)(unsafe.Pointer(moduleBase + uintptr(peOff)))
	if nt[0] != 'P' || nt[1] != 'E' {
		return 0, 0
	}

	// Optional header starts after 4-byte Signature and 20-byte COFF header
	optStart := moduleBase + uintptr(peOff) + 24
	magic := *(*uint16)(unsafe.Pointer(optStart + 0))

	var ddOff uintptr
	// DataDirectory starts at offset 96 for PE32, 112 for PE32+
	if magic == 0x10b { // PE32
		ddOff = 96
	} else if magic == 0x20b { // PE32+
		ddOff = 112
	} else {
		return 0, 0
	}

	// IMAGE_DIRECTORY_ENTRY_EXPORT = 0
	dd := optStart + ddOff
	exportRVA := *(*uint32)(unsafe.Pointer(dd + 0))
	exportSize := *(*uint32)(unsafe.Pointer(dd + 4))
	return exportRVA, exportSize
}

// parseExports enumerates exports directly from an in-memory module image
func parseExports(moduleBase uintptr) []Export {
	exportRVA, _ := getExportDirectoryRange(moduleBase)
	if exportRVA == 0 {
		return nil
	}

	exportDir := moduleBase + uintptr(exportRVA)

	// Offsets within IMAGE_EXPORT_DIRECTORY
	// 16: Base (DWORD)
	// 20: NumberOfFunctions (DWORD)
	// 24: NumberOfNames (DWORD)
	// 28: AddressOfFunctions (DWORD)
	// 32: AddressOfNames (DWORD)
	// 36: AddressOfNameOrdinals (DWORD)
	base := *(*uint32)(unsafe.Pointer(exportDir + 16))
	numFuncs := *(*uint32)(unsafe.Pointer(exportDir + 20))
	numNames := *(*uint32)(unsafe.Pointer(exportDir + 24))
	addrFuncsRVA := *(*uint32)(unsafe.Pointer(exportDir + 28))
	addrNamesRVA := *(*uint32)(unsafe.Pointer(exportDir + 32))
	addrOrdsRVA := *(*uint32)(unsafe.Pointer(exportDir + 36))

	addrFuncs := moduleBase + uintptr(addrFuncsRVA)
	addrNames := moduleBase + uintptr(addrNamesRVA)
	addrOrds := moduleBase + uintptr(addrOrdsRVA)

	// Build a map of function index -> name
	nameByIndex := make(map[uint16]string)
	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(addrNames + uintptr(i*4)))
		namePtr := moduleBase + uintptr(nameRVA)
		// Ordinal index is a WORD into AddressOfFunctions table
		ordIndex := *(*uint16)(unsafe.Pointer(addrOrds + uintptr(i*2)))
		nameByIndex[ordIndex] = readCString(namePtr)
	}

	// Collect all exports (including ordinal-only)
	exports := make([]Export, 0, numFuncs)
	for i := uint32(0); i < numFuncs; i++ {
		funcRVA := *(*uint32)(unsafe.Pointer(addrFuncs + uintptr(i*4)))
		if funcRVA == 0 {
			continue
		}
		name := ""
		if n, ok := nameByIndex[uint16(i)]; ok {
			name = n
		}
		exports = append(exports, Export{
			Name:           name,
			VirtualAddress: funcRVA,
			Ordinal:        base + i,
		})
	}
	return exports
}

func readCString(ptr uintptr) string {
	// Read ASCII bytes until NUL or a sane limit
	var buf [512]byte
	for i := 0; i < len(buf); i++ {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if b == 0 {
			return string(buf[:i])
		}
		buf[i] = b
	}
	return string(buf[:])
}

// API Set structures for dynamic resolution
type API_SET_NAMESPACE struct {
	Version     uint32
	Size        uint32
	Flags       uint32
	Count       uint32
	EntryOffset uint32
	HashOffset  uint32
	HashFactor  uint32
}

type API_SET_NAMESPACE_ENTRY struct {
	Flags        uint32
	NameOffset   uint32
	NameLength   uint32
	HashedLength uint32
	ValueOffset  uint32
	ValueCount   uint32
}

type API_SET_VALUE_ENTRY struct {
	Flags       uint32
	NameOffset  uint32
	NameLength  uint32
	ValueOffset uint32
	ValueLength uint32
}

type funcCacheKey struct {
	moduleBase   uintptr
	functionHash uint32
}

var (
	moduleCache        = make(map[uint32]uintptr)
	moduleCacheMutex   sync.RWMutex
	functionCache      = make(map[funcCacheKey]uintptr)
	functionCacheMutex sync.RWMutex
	exportIndexCache   = make(map[uintptr]*exportIndex)
	exportIndexMutex   sync.RWMutex

	moduleListCache     []moduleInfo
	moduleListCacheTime int64
	moduleListMutex     sync.RWMutex

	loadLibraryCallback func(string) uintptr
)

type moduleInfo struct {
	hash uint32
	base uintptr
}

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
	// Fast path: check individual module cache first
	moduleCacheMutex.RLock()
	if moduleBase, ok := moduleCache[moduleHash]; ok {
		moduleCacheMutex.RUnlock()
		return moduleBase
	}
	moduleCacheMutex.RUnlock()

	// Check module list cache (avoids PEB walk if recent)
	now := time.Now().UnixNano()
	moduleListMutex.RLock()
	if moduleListCacheTime != 0 && (now-moduleListCacheTime) < 5e9 { // 5 second cache
		for _, mod := range moduleListCache {
			if mod.hash == moduleHash {
				moduleListMutex.RUnlock()
				// Also cache in individual cache for faster future access
				moduleCacheMutex.Lock()
				moduleCache[moduleHash] = mod.base
				moduleCacheMutex.Unlock()
				return mod.base
			}
		}
	}
	moduleListMutex.RUnlock()

	// Slow path: refresh module list cache
	return refreshModuleCache(moduleHash)
}

func refreshModuleCache(targetHash uint32) uintptr {
	peb := GetCurrentProcessPEB()
	if peb == nil || peb.Ldr == nil {
		return 0
	}

	var newModuleList []moduleInfo
	var targetBase uintptr

	entry := &peb.Ldr.InLoadOrderModuleList
	currentEntry := entry.Flink

	for currentEntry != nil && currentEntry != entry {
		dataTableEntry := (*utils.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(currentEntry))

		baseName := utils.UTF16ToString(dataTableEntry.BaseDllName.Buffer)
		currentHash := obf.GetHash(baseName)

		newModuleList = append(newModuleList, moduleInfo{
			hash: currentHash,
			base: dataTableEntry.DllBase,
		})

		if currentHash == targetHash {
			targetBase = dataTableEntry.DllBase
		}

		currentEntry = currentEntry.Flink
	}

	// Update cache
	moduleListMutex.Lock()
	moduleListCache = newModuleList
	moduleListCacheTime = time.Now().UnixNano()
	moduleListMutex.Unlock()

	// Cache individual result
	if targetBase != 0 {
		moduleCacheMutex.Lock()
		moduleCache[targetHash] = targetBase
		moduleCacheMutex.Unlock()
	}

	return targetBase
}

func GetFunctionAddress(moduleBase uintptr, functionHash uint32) uintptr {
	// Use struct key to avoid string allocation
	cacheKey := funcCacheKey{moduleBase: moduleBase, functionHash: functionHash}
	functionCacheMutex.RLock()
	if funcAddr, ok := functionCache[cacheKey]; ok {
		functionCacheMutex.RUnlock()
		return funcAddr
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

	// Resolve using cached export index for O(1) lookups
	idx := getExportIndex(moduleBase)
	if idx == nil {
		return 0
	}

	var funcAddr uintptr
	var foundExport *Export

	if functionHash < 65536 {
		if exp, ok := idx.ord[functionHash]; ok {
			e := exp
			foundExport = &e
		}
	}

	if foundExport == nil {
		if exp, ok := idx.name[functionHash]; ok {
			e := exp
			foundExport = &e
		}
	}

	if foundExport != nil {
		funcAddr = moduleBase + uintptr(foundExport.VirtualAddress)

		if isForwardedExport(moduleBase, funcAddr) {
			forwarderString := getForwarderString(funcAddr)
			if resolvedAddr := resolveForwardedExport(forwarderString); resolvedAddr != 0 {
				funcAddr = resolvedAddr
			}
		}
	}

	if funcAddr != 0 {
		functionCacheMutex.Lock()
		functionCache[cacheKey] = funcAddr
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
			// Found match, choose best value entry
			if entry.ValueCount == 0 {
				continue
			}

			bestName := ""
			valuesBase := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(entry.ValueOffset)
			for k := uint32(0); k < entry.ValueCount; k++ {
				ve := (*API_SET_VALUE_ENTRY)(unsafe.Pointer(valuesBase + uintptr(k)*unsafe.Sizeof(API_SET_VALUE_ENTRY{})))

				realDllPtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(ve.ValueOffset)
				realDllBytes := (*[256]uint16)(unsafe.Pointer(realDllPtr))
				realDllLen := ve.ValueLength / 2
				if realDllLen == 0 || realDllLen > 256 {
					continue
				}

				// If NameLength>0 this is a host-specific override; prefer the first such entry
				dllSlice := make([]uint16, realDllLen)
				for j := uint32(0); j < realDllLen; j++ {
					dllSlice[j] = realDllBytes[j]
				}
				realDllName := utils.UTF16ToString(&dllSlice[0])

				if !strings.HasSuffix(strings.ToLower(realDllName), ".dll") {
					realDllName += ".dll"
				}

				if ve.NameLength > 0 {
					return realDllName
				}
				if bestName == "" {
					bestName = realDllName
				}
			}
			if bestName != "" {
				return bestName
			}
		}
	}

	// If not found, try to find a similar API Set with a different version
	// Extract the base name (without version) for fallback matching
	// e.g., "api-ms-win-core-com-l1-1-0" -> "api-ms-win-core-com"
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

func isForwardedExport(moduleBase, funcAddr uintptr) bool {
	exportRVA, exportSize := getExportDirectoryRange(moduleBase)
	if exportRVA == 0 || exportSize == 0 {
		return false
	}
	rva := uint32(funcAddr - moduleBase)
	return rva >= exportRVA && rva < exportRVA+exportSize
}

type exportIndex struct {
	name map[uint32]Export // hash(name) -> export
	ord  map[uint32]Export // ordinal -> export
}

func getExportIndex(moduleBase uintptr) *exportIndex {
	if moduleBase == 0 {
		return nil
	}
	exportIndexMutex.RLock()
	if idx, ok := exportIndexCache[moduleBase]; ok {
		exportIndexMutex.RUnlock()
		return idx
	}
	exportIndexMutex.RUnlock()

	exports := parseExports(moduleBase)
	if len(exports) == 0 {
		return nil
	}
	nameMap := make(map[uint32]Export, len(exports))
	ordMap := make(map[uint32]Export, len(exports))
	for _, e := range exports {
		if e.Name != "" {
			nameMap[obf.GetHash(e.Name)] = e
		}
		ordMap[e.Ordinal] = e
	}
	idx := &exportIndex{name: nameMap, ord: ordMap}
	exportIndexMutex.Lock()
	exportIndexCache[moduleBase] = idx
	exportIndexMutex.Unlock()
	return idx
}

// ClearResolveCaches clears resolve-level caches to avoid stale results
func ClearResolveCaches() {
	moduleCacheMutex.Lock()
	moduleCache = make(map[uint32]uintptr)
	moduleCacheMutex.Unlock()

	functionCacheMutex.Lock()
	functionCache = make(map[funcCacheKey]uintptr)
	functionCacheMutex.Unlock()

	exportIndexMutex.Lock()
	exportIndexCache = make(map[uintptr]*exportIndex)
	exportIndexMutex.Unlock()

	moduleListMutex.Lock()
	moduleListCache = nil
	moduleListCacheTime = 0
	moduleListMutex.Unlock()
}

func getForwarderString(funcAddr uintptr) string {
	// Use fixed buffer to avoid slice growth allocations
	var buf [256]byte
	ptr := (*byte)(unsafe.Pointer(funcAddr))

	for i := 0; i < len(buf); i++ {
		if *ptr == 0 {
			return string(buf[:i])
		}
		buf[i] = *ptr
		ptr = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1))
	}

	return string(buf[:])
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
