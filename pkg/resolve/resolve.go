package resolve

import (
	"runtime"
	"sync"
	_ "unsafe"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/utils"
)

// nanotime returns monotonic time in nanoseconds without allocation :3
// using linkname avoids time.Now() which allocates
//
//go:linkname nanotime runtime.nanotime
func nanotime() int64

type Export struct {
	Name           string
	VirtualAddress uint32
	Ordinal        uint32
}

func getExportDirectoryRange(moduleBase uintptr) (uint32, uint32) {
	if moduleBase == 0 {
		return 0, 0
	}

	dos := (*[64]byte)(unsafe.Pointer(moduleBase))
	if dos[0] != 'M' || dos[1] != 'Z' {
		return 0, 0
	}

	peOff := *(*uint32)(unsafe.Pointer(moduleBase + 0x3C))
	nt := (*[256]byte)(unsafe.Pointer(moduleBase + uintptr(peOff)))
	if nt[0] != 'P' || nt[1] != 'E' {
		return 0, 0
	}

	optStart := moduleBase + uintptr(peOff) + 24
	magic := *(*uint16)(unsafe.Pointer(optStart + 0))

	var ddOff uintptr
	if magic == 0x10b { // pe32
		ddOff = 96
	} else if magic == 0x20b { // pe32+
		ddOff = 112
	} else {
		return 0, 0
	}

	dd := optStart + ddOff
	exportRVA := *(*uint32)(unsafe.Pointer(dd + 0))
	exportSize := *(*uint32)(unsafe.Pointer(dd + 4))
	return exportRVA, exportSize
}

// exportWithHash pairs an export with its pre computed name hash :p
// this avoids materializing go strings for hash lookups
type exportWithHash struct {
	exp      *Export
	nameHash uint32
}

// parseExportsWithHashes parses exports and computes name hashes directly from c strings :3
// this eliminates the allocation that would occur from readCString + GetHash for every export
// names are stored as zero copy pointers into module memory using unsafe.String
func parseExportsWithHashes(moduleBase uintptr) []exportWithHash {
	exportRVA, _ := getExportDirectoryRange(moduleBase)
	if exportRVA == 0 {
		return nil
	}

	exportDir := moduleBase + uintptr(exportRVA)
	base := *(*uint32)(unsafe.Pointer(exportDir + 16))
	numFuncs := *(*uint32)(unsafe.Pointer(exportDir + 20))
	numNames := *(*uint32)(unsafe.Pointer(exportDir + 24))
	addrFuncsRVA := *(*uint32)(unsafe.Pointer(exportDir + 28))
	addrNamesRVA := *(*uint32)(unsafe.Pointer(exportDir + 32))
	addrOrdsRVA := *(*uint32)(unsafe.Pointer(exportDir + 36))

	addrFuncs := moduleBase + uintptr(addrFuncsRVA)
	addrNames := moduleBase + uintptr(addrNamesRVA)
	addrOrds := moduleBase + uintptr(addrOrdsRVA)

	// use slices instead of maps cuz ordinals are dense and bounded by numFuncs :p
	// this avoids map bucket allocations and improves cache locality
	nameHashByIndex := make([]uint32, numFuncs)
	namePtrByIndex := make([]uintptr, numFuncs)
	nameLenByIndex := make([]int, numFuncs)

	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(addrNames + uintptr(i*4)))
		namePtr := moduleBase + uintptr(nameRVA)
		ordIndex := *(*uint16)(unsafe.Pointer(addrOrds + uintptr(i*2)))
		if uint32(ordIndex) < numFuncs {
			// hash directly from c string, no go string allocation :3
			nameHashByIndex[ordIndex] = obf.HashFromCString(namePtr)
			namePtrByIndex[ordIndex] = namePtr
			// get length for zero copy string later
			nameLenByIndex[ordIndex] = cStringLen(namePtr)
		}
	}

	exports := make([]exportWithHash, 0, numFuncs)
	for i := uint32(0); i < numFuncs; i++ {
		funcRVA := *(*uint32)(unsafe.Pointer(addrFuncs + uintptr(i*4)))
		if funcRVA == 0 {
			continue
		}
		exp := &Export{
			VirtualAddress: funcRVA,
			Ordinal:        base + i,
		}
		// zero copy string from module memory, no allocation :p
		if namePtrByIndex[i] != 0 && nameLenByIndex[i] > 0 {
			exp.Name = unsafe.String((*byte)(unsafe.Pointer(namePtrByIndex[i])), nameLenByIndex[i])
		}
		exports = append(exports, exportWithHash{
			exp:      exp,
			nameHash: nameHashByIndex[i],
		})
	}
	return exports
}

// cStringLen returns length of null terminated c string without allocating
func cStringLen(ptr uintptr) int {
	for i := 0; ; i++ {
		if *(*byte)(unsafe.Pointer(ptr + uintptr(i))) == 0 {
			return i
		}
		if i >= 512 {
			return i
		}
	}
}

func readCString(ptr uintptr) string {
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

// packCacheKey packs moduleBase and functionHash into a single uint64 :0
// on 64 bit systems, we use lower 32 bits of moduleBase (sufficient for module alignment)
// combined with functionHash in upper 32 bits. this improves map hashing speed
// and reduces memory vs a struct key with padding
func packCacheKey(moduleBase uintptr, functionHash uint32) uint64 {
	return uint64(uint32(moduleBase)) | (uint64(functionHash) << 32)
}

var (
	moduleCache        = make(map[uint32]uintptr)
	moduleCacheMutex   sync.RWMutex
	functionCache      = make(map[uint64]uintptr) // packed key for better hash performance :3
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

	peb := (*utils.PEB)(unsafe.Pointer(pebAddr))
	if peb != nil && peb.Ldr != nil {
		return peb
	}

	// spin with gosched instead of time.sleep :p
	// this runs early and rarely fails. gosched keeps us on the same thread
	// and avoids timer heap activity that sleep incurs
	maxRetries := 50 // more iterations but much faster per iteration
	for i := 0; i < maxRetries; i++ {
		runtime.Gosched()
		peb = (*utils.PEB)(unsafe.Pointer(pebAddr))
		if peb != nil && peb.Ldr != nil {
			return peb
		}
	}

	return peb
}

func GetModuleBase(moduleHash uint32) uintptr {
	moduleCacheMutex.RLock()
	if moduleBase, ok := moduleCache[moduleHash]; ok {
		moduleCacheMutex.RUnlock()
		return moduleBase
	}
	moduleCacheMutex.RUnlock()

	now := nanotime()
	moduleListMutex.RLock()
	if moduleListCacheTime != 0 && (now-moduleListCacheTime) < 5e9 { // 5 second cache
		for _, mod := range moduleListCache {
			if mod.hash == moduleHash {
				moduleListMutex.RUnlock()
				moduleCacheMutex.Lock()
				moduleCache[moduleHash] = mod.base
				moduleCacheMutex.Unlock()
				return mod.base
			}
		}
	}
	moduleListMutex.RUnlock()

	// double check pattern: acquire write lock and re check before doing expensive refresh :3
	// this prevents multiple goroutines from doing redundant refreshModuleCache calls
	moduleCacheMutex.Lock()
	if moduleBase, ok := moduleCache[moduleHash]; ok {
		moduleCacheMutex.Unlock()
		return moduleBase
	}
	moduleCacheMutex.Unlock()

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

		// hash directly from utf16, no string allocation :3
		currentHash := obf.HashFromUTF16(uintptr(unsafe.Pointer(dataTableEntry.BaseDllName.Buffer)))

		newModuleList = append(newModuleList, moduleInfo{
			hash: currentHash,
			base: dataTableEntry.DllBase,
		})

		if currentHash == targetHash {
			targetBase = dataTableEntry.DllBase
		}

		currentEntry = currentEntry.Flink
	}

	moduleListMutex.Lock()
	moduleListCache = newModuleList
	moduleListCacheTime = nanotime()
	moduleListMutex.Unlock()

	if targetBase != 0 {
		moduleCacheMutex.Lock()
		moduleCache[targetHash] = targetBase
		moduleCacheMutex.Unlock()
	}

	return targetBase
}

func GetFunctionAddress(moduleBase uintptr, functionHash uint32) uintptr {
	cacheKey := packCacheKey(moduleBase, functionHash)
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
	idx := getExportIndex(moduleBase)
	if idx == nil {
		return 0
	}

	var funcAddr uintptr
	var foundExport *Export

	// try ordinal lookup first using slice for o(1) access :p
	if functionHash < 65536 {
		ordIdx := int(functionHash) - int(idx.ordBase)
		if ordIdx >= 0 && ordIdx < len(idx.ord) {
			foundExport = idx.ord[ordIdx]
		}
	}

	if foundExport == nil {
		foundExport = idx.name[functionHash]
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

// utf16EqualFoldASCII compares a utf16 string at ptr (length utf16Len) with an ascii string :3
// case insensitive comparison. api set names are ascii, so this is safe
// no allocations. asciiStr can be mixed case, comparison lowercases both sides
func utf16EqualFoldASCII(ptr uintptr, utf16Len uint32, asciiStr string, asciiLen int) bool {
	if int(utf16Len) != asciiLen {
		return false
	}
	for i := 0; i < asciiLen; i++ {
		c := *(*uint16)(unsafe.Pointer(ptr + uintptr(i*2)))
		if c > 127 {
			return false // non ascii, can't match
		}
		b := byte(c)
		if b >= 'A' && b <= 'Z' {
			b = b + 0x20
		}
		a := asciiStr[i]
		if a >= 'A' && a <= 'Z' {
			a = a + 0x20
		}
		if b != a {
			return false
		}
	}
	return true
}

// utf16HasPrefixFoldASCII checks if utf16 at ptr starts with ascii prefix (case insensitive)
func utf16HasPrefixFoldASCII(ptr uintptr, utf16Len uint32, asciiPrefix string) bool {
	if int(utf16Len) < len(asciiPrefix) {
		return false
	}
	for i := 0; i < len(asciiPrefix); i++ {
		c := *(*uint16)(unsafe.Pointer(ptr + uintptr(i*2)))
		if c > 127 {
			return false
		}
		b := byte(c)
		if b >= 'A' && b <= 'Z' {
			b = b + 0x20
		}
		a := asciiPrefix[i]
		if a >= 'A' && a <= 'Z' {
			a = a + 0x20
		}
		if b != a {
			return false
		}
	}
	return true
}

// utf16HasPrefixFoldASCIIWithSuffix checks if utf16 starts with ascii[:prefixLen] + "-l" :p
// this avoids allocating a concatenated string for the prefix check
func utf16HasPrefixFoldASCIIWithSuffix(ptr uintptr, utf16Len uint32, ascii string, prefixLen int) bool {
	// need at least prefixLen + 2 chars for base + "-l"
	if int(utf16Len) < prefixLen+2 {
		return false
	}
	// check base prefix
	for i := 0; i < prefixLen; i++ {
		c := *(*uint16)(unsafe.Pointer(ptr + uintptr(i*2)))
		if c > 127 {
			return false
		}
		b := byte(c)
		if b >= 'A' && b <= 'Z' {
			b = b + 0x20
		}
		a := ascii[i]
		if a >= 'A' && a <= 'Z' {
			a = a + 0x20
		}
		if b != a {
			return false
		}
	}
	// check "-l" suffix
	c1 := *(*uint16)(unsafe.Pointer(ptr + uintptr(prefixLen*2)))
	c2 := *(*uint16)(unsafe.Pointer(ptr + uintptr((prefixLen+1)*2)))
	if c1 != '-' {
		return false
	}
	if c2 != 'l' && c2 != 'L' {
		return false
	}
	return true
}

// utf16ToStringDirect reads utf16 from ptr with known length into a go string
// this still allocates, but only when we actually need the result string :p
func utf16ToStringDirect(ptr uintptr, utf16Len uint32) string {
	if utf16Len == 0 || utf16Len > 256 {
		return ""
	}
	// build string, we only call this when we're returning a result
	buf := make([]byte, 0, utf16Len)
	for i := uint32(0); i < utf16Len; i++ {
		c := *(*uint16)(unsafe.Pointer(ptr + uintptr(i*2)))
		if c == 0 {
			break
		}
		if c < 128 {
			buf = append(buf, byte(c))
		} else {
			// handle non ascii, rare for dll names
			if c < 0x800 {
				buf = append(buf, byte(0xC0|(c>>6)), byte(0x80|(c&0x3F)))
			} else {
				buf = append(buf, byte(0xE0|(c>>12)), byte(0x80|((c>>6)&0x3F)), byte(0x80|(c&0x3F)))
			}
		}
	}
	return string(buf)
}

// hasDllSuffixFold checks if string ends with ".dll" case insensitively without allocation :3
func hasDllSuffixFold(s string) bool {
	if len(s) < 4 {
		return false
	}
	suffix := s[len(s)-4:]
	return suffix[0] == '.' &&
		(suffix[1] == 'd' || suffix[1] == 'D') &&
		(suffix[2] == 'l' || suffix[2] == 'L') &&
		(suffix[3] == 'l' || suffix[3] == 'L')
}

// asciiEqualFold compares two ascii strings case insensitively without allocation :p
// replacement for strings.EqualFold which allocates internally
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca = ca + 0x20
		}
		if cb >= 'A' && cb <= 'Z' {
			cb = cb + 0x20
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func resolveApiSet(dllName string) string {
	// check api ms prefix without allocation
	if len(dllName) < 7 {
		return dllName
	}
	prefix := dllName[:7]
	if !((prefix[0] == 'a' || prefix[0] == 'A') &&
		(prefix[1] == 'p' || prefix[1] == 'P') &&
		(prefix[2] == 'i' || prefix[2] == 'I') &&
		prefix[3] == '-' &&
		(prefix[4] == 'm' || prefix[4] == 'M') &&
		(prefix[5] == 's' || prefix[5] == 'S') &&
		prefix[6] == '-') {
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

	// compute search name bounds, strip .dll suffix if present
	// no allocation needed, we compare inline with lowercasing :3
	searchLen := len(dllName)
	if hasDllSuffixFold(dllName) {
		searchLen = len(dllName) - 4
	}

	entryPtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(apiSetMap.EntryOffset)

	for i := uint32(0); i < apiSetMap.Count; i++ {
		entry := (*API_SET_NAMESPACE_ENTRY)(unsafe.Pointer(entryPtr + uintptr(i)*unsafe.Sizeof(API_SET_NAMESPACE_ENTRY{})))
		namePtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(entry.NameOffset)
		nameLen := entry.NameLength / 2 // convert from bytes to utf16 chars

		if nameLen > 256 {
			continue
		}

		// compare utf16 directly with our search string, inline lowercasing, no allocation :3
		if utf16EqualFoldASCII(namePtr, nameLen, dllName, searchLen) {
			if entry.ValueCount == 0 {
				continue
			}

			bestName := ""
			valuesBase := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(entry.ValueOffset)
			for k := uint32(0); k < entry.ValueCount; k++ {
				ve := (*API_SET_VALUE_ENTRY)(unsafe.Pointer(valuesBase + uintptr(k)*unsafe.Sizeof(API_SET_VALUE_ENTRY{})))

				realDllPtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(ve.ValueOffset)
				realDllLen := ve.ValueLength / 2
				if realDllLen == 0 || realDllLen > 256 {
					continue
				}

				// only allocate string when we're about to return
				realDllName := utf16ToStringDirect(realDllPtr, realDllLen)

				if !hasDllSuffixFold(realDllName) {
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

	// fallback: find similar api set with different version
	// e.g., "api ms win core com l1 1 0" -> "api ms win core com"
	// find base name end index (before "-l" suffix) without allocating
	baseEndIdx := searchLen
	for i := searchLen - 1; i >= 2; i-- {
		c := dllName[i]
		if c >= 'A' && c <= 'Z' {
			c = c + 0x20
		}
		if c == 'l' && dllName[i-1] == '-' {
			baseEndIdx = i - 1
			break
		}
	}

	for i := uint32(0); i < apiSetMap.Count; i++ {
		entry := (*API_SET_NAMESPACE_ENTRY)(unsafe.Pointer(entryPtr + uintptr(i)*unsafe.Sizeof(API_SET_NAMESPACE_ENTRY{})))
		namePtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(entry.NameOffset)
		nameLen := entry.NameLength / 2

		if nameLen > 0 && nameLen < 100 {
			// check if this is a version variant of our target (starts with base + "-l")
			if utf16HasPrefixFoldASCIIWithSuffix(namePtr, nameLen, dllName, baseEndIdx) {
				if entry.ValueCount > 0 {
					valuePtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(entry.ValueOffset)
					value := (*API_SET_VALUE_ENTRY)(unsafe.Pointer(valuePtr))

					realDllPtr := uintptr(unsafe.Pointer(apiSetMap)) + uintptr(value.ValueOffset)
					realDllLen := value.ValueLength / 2

					if realDllLen > 0 && realDllLen < 256 {
						fallbackDLL := utf16ToStringDirect(realDllPtr, realDllLen)
						if !hasDllSuffixFold(fallbackDLL) {
							fallbackDLL += ".dll"
						}
						return fallbackDLL
					}
				}
			}
		}
	}

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
	name    map[uint32]*Export // hash(name) -> export
	ord     []*Export          // ordinal -> export, slice for dense lookup :3
	ordBase uint32             // base ordinal, ord[i] = ordinal ordBase+i
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

	// double check pattern: re check under write lock to avoid redundant work :0
	exportIndexMutex.Lock()
	if idx, ok := exportIndexCache[moduleBase]; ok {
		exportIndexMutex.Unlock()
		return idx
	}

	exports := parseExportsWithHashes(moduleBase)
	if len(exports) == 0 {
		exportIndexMutex.Unlock()
		return nil
	}

	// count named exports and find ordinal range to size allocations properly :p
	namedCount := 0
	minOrd := uint32(0xFFFFFFFF)
	maxOrd := uint32(0)
	for _, e := range exports {
		if e.nameHash != 0 {
			namedCount++
		}
		if e.exp.Ordinal < minOrd {
			minOrd = e.exp.Ordinal
		}
		if e.exp.Ordinal > maxOrd {
			maxOrd = e.exp.Ordinal
		}
	}

	nameMap := make(map[uint32]*Export, namedCount)
	// use slice for ordinals, much faster than map for dense integer keys :3
	ordSlice := make([]*Export, maxOrd-minOrd+1)
	for _, e := range exports {
		if e.nameHash != 0 {
			nameMap[e.nameHash] = e.exp
		}
		ordSlice[e.exp.Ordinal-minOrd] = e.exp
	}
	idx := &exportIndex{name: nameMap, ord: ordSlice, ordBase: minOrd}
	exportIndexCache[moduleBase] = idx
	exportIndexMutex.Unlock()
	return idx
}

// ClearResolveCaches clears resolve level caches to avoid stale results :p
func ClearResolveCaches() {
	moduleCacheMutex.Lock()
	moduleCache = make(map[uint32]uintptr)
	moduleCacheMutex.Unlock()

	functionCacheMutex.Lock()
	functionCache = make(map[uint64]uintptr)
	functionCacheMutex.Unlock()

	exportIndexMutex.Lock()
	exportIndexCache = make(map[uintptr]*exportIndex)
	exportIndexMutex.Unlock()

	moduleListMutex.Lock()
	moduleListCache = nil
	moduleListCacheTime = 0
	moduleListMutex.Unlock()
}

// getForwarderString reads a c string from module memory using unsafe.String for zero copy :3
// the backing memory is the loaded module which stays valid, so this is safe
// go 1.20+ required for unsafe.String
func getForwarderString(funcAddr uintptr) string {
	// first find the length
	length := 0
	for {
		if *(*byte)(unsafe.Pointer(funcAddr + uintptr(length))) == 0 {
			break
		}
		length++
		if length >= 256 {
			break
		}
	}
	if length == 0 {
		return ""
	}
	// zero copy string from module memory, the module stays loaded :p
	return unsafe.String((*byte)(unsafe.Pointer(funcAddr)), length)
}

func resolveForwardedExport(forwarderString string) uintptr {
	// use slice with small initial capacity, forwarding chains are typically shallow
	return resolveForwardedExportWithStack(forwarderString, make([]string, 0, 4))
}

func resolveForwardedExportWithStack(forwarderString string, resolutionStack []string) uintptr {
	// check for circular forwarding using linear scan, depth is tiny in practice :3
	// this avoids map allocation and hashing overhead
	for _, s := range resolutionStack {
		if s == forwarderString {
			return 0 // circular reference detected
		}
	}

	// manual dot scan instead of strings.Split, forwarder strings are tiny and always have exactly one dot
	dotIdx := -1
	for i := 0; i < len(forwarderString); i++ {
		if forwarderString[i] == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx <= 0 || dotIdx >= len(forwarderString)-1 {
		return 0
	}

	targetDLL := forwarderString[:dotIdx]
	targetFunction := forwarderString[dotIdx+1:]

	// check for .dll suffix without allocation, ascii case fold
	needsDllSuffix := true
	if len(targetDLL) >= 4 {
		suffix := targetDLL[len(targetDLL)-4:]
		if suffix[0] == '.' &&
			(suffix[1] == 'd' || suffix[1] == 'D') &&
			(suffix[2] == 'l' || suffix[2] == 'L') &&
			(suffix[3] == 'l' || suffix[3] == 'L') {
			needsDllSuffix = false
		}
	}
	if needsDllSuffix {
		targetDLL += ".dll"
	}

	// handle api set dlls, resolve them to their actual implementation
	actualDLL := resolveApiSet(targetDLL)

	// avoid circular resolution: if the api set resolves back to the same dll
	// that we're already resolving from, try loading the original api set dll
	var dllHash uint32
	var moduleBase uintptr

	if asciiEqualFold(actualDLL, targetDLL) {
		// api set couldn't be resolved, try loading it directly
		dllHash = obf.GetHash(targetDLL)
		moduleBase = GetModuleBase(dllHash)
		if moduleBase == 0 && loadLibraryCallback != nil {
			loadLibraryCallback(targetDLL)
			moduleBase = GetModuleBase(dllHash)
		}
	} else {
		dllHash = obf.GetHash(actualDLL)
		moduleBase = GetModuleBase(dllHash)
		if moduleBase == 0 && loadLibraryCallback != nil {
			loadLibraryCallback(actualDLL)
			moduleBase = GetModuleBase(dllHash)
		}
	}

	if moduleBase == 0 {
		return 0
	}

	// add to stack for recursive calls, no defer needed, slice append is sufficient
	resolutionStack = append(resolutionStack, forwarderString)

	if len(targetFunction) > 0 && targetFunction[0] == '#' {
		// parse ordinal manually to avoid strconv.ParseUint allocation :3
		ordinal := uint32(0)
		for i := 1; i < len(targetFunction); i++ {
			c := targetFunction[i]
			if c < '0' || c > '9' {
				return 0
			}
			ordinal = ordinal*10 + uint32(c-'0')
		}
		return getFunctionAddressWithForwardStack(moduleBase, ordinal, resolutionStack)
	}
	funcHash := obf.GetHash(targetFunction)
	return getFunctionAddressWithForwardStack(moduleBase, funcHash, resolutionStack)
}

// getFunctionAddressWithForwardStack resolves function addresses while tracking forwarded export chains
// to prevent infinite recursion during forwarded export resolution :0
func getFunctionAddressWithForwardStack(moduleBase uintptr, functionHash uint32, resolutionStack []string) uintptr {
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

	// resolve using cached export index for o(1) lookups
	idx := getExportIndex(moduleBase)
	if idx == nil {
		return 0
	}

	var funcAddr uintptr
	var foundExport *Export

	// try ordinal lookup first using slice for o(1) access :3
	if functionHash < 65536 {
		ordIdx := int(functionHash) - int(idx.ordBase)
		if ordIdx >= 0 && ordIdx < len(idx.ord) {
			foundExport = idx.ord[ordIdx]
		}
	}

	if foundExport == nil {
		foundExport = idx.name[functionHash]
	}

	if foundExport != nil {
		funcAddr = moduleBase + uintptr(foundExport.VirtualAddress)

		if isForwardedExport(moduleBase, funcAddr) {
			forwarderString := getForwarderString(funcAddr)
			if resolvedAddr := resolveForwardedExportWithStack(forwarderString, resolutionStack); resolvedAddr != 0 {
				funcAddr = resolvedAddr
			}
		}
	}

	return funcAddr
}
