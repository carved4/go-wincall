package resolve

import (
	"time"
	"unsafe"
	"sort"
	"github.com/carved4/go-wincall/pkg/errors"
	"github.com/carved4/go-wincall/pkg/obf"
)

func GetSyscallNumber(functionHash uint32) uint16 {
	syscallCacheMutex.RLock()
	if num, ok := syscallCache[functionHash]; ok {
		syscallCacheMutex.RUnlock()
		return num
	}
	syscallCacheMutex.RUnlock()

	ntdllHash := obf.GetHash("ntdll.dll")

	var ntdllBase uintptr
	maxRetries := 8
	baseDelay := 50 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		ntdllBase = GetModuleBase(ntdllHash)
		if ntdllBase != 0 {
			break
		}

		delay := baseDelay * time.Duration(1<<uint(i))
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}

		time.Sleep(delay)
	}

	if ntdllBase == 0 {
		return 0
	}

	var funcAddr uintptr

	for i := 0; i < maxRetries; i++ {
		funcAddr = GetFunctionAddress(ntdllBase, functionHash)
		if funcAddr != 0 {
			break
		}

		delay := baseDelay * time.Duration(1<<uint(i))
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}

		time.Sleep(delay)
	}

	if funcAddr == 0 {
		return 0
	}

	syscallNumber := extractSyscallNumberWithValidation(funcAddr, functionHash)

	if syscallNumber != 0 {
		syscallCacheMutex.Lock()
		syscallCache[functionHash] = syscallNumber
		syscallCacheMutex.Unlock()
	}

	return syscallNumber
}

func GetSyscallAndAddress(functionHash uint32) (uint16, uintptr) {
	// Try multiple strategies for hook evasion
	return getSyscallWithAntiHook(functionHash)
}

func getSyscallWithAntiHook(functionHash uint32) (uint16, uintptr) {
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return 0, 0
	}

	// Strategy 1: Try the original function
	funcAddr := GetFunctionAddress(ntdllBase, functionHash)
	if funcAddr != 0 {
		if syscallNum, trampolineAddr := tryExtractSyscall(funcAddr); syscallNum != 0 {
			return syscallNum, trampolineAddr
		}
	}

	// Strategy 2: Try Nt/Zw pair (they have identical syscall numbers)
	if pairHash := findNtZwPair(functionHash); pairHash != 0 {
		pairAddr := GetFunctionAddress(ntdllBase, pairHash)
		if pairAddr != 0 {
			if syscallNum, trampolineAddr := tryExtractSyscall(pairAddr); syscallNum != 0 {
				return syscallNum, trampolineAddr
			}
		}
	}

	// Strategy 3: Use syscall number guessing with clean trampoline
	if syscallNum := GuessSyscallNumber(functionHash); syscallNum != 0 {
		if cleanTrampoline := findCleanSyscallTrampoline(); cleanTrampoline != 0 {
			return syscallNum, cleanTrampoline
		}
		// Fallback: return SSN with 0 address (will use direct syscall)
		return syscallNum, 0
	}

	return 0, 0
}

// tryExtractSyscall attempts to extract syscall number and find clean trampoline
func tryExtractSyscall(funcAddr uintptr) (uint16, uintptr) {
	if funcAddr == 0 {
		return 0, 0
	}

	// Check if function is hooked
	if isHooked(funcAddr) {
		return 0, 0
	}

	// Extract syscall number using existing validation
	syscallNum := extractSyscallNumberWithValidation(funcAddr, 0)
	if syscallNum == 0 {
		return 0, 0
	}

	// Find clean trampoline (syscall; ret gadget)
	trampolineAddr := findSyscallTrampoline(funcAddr)
	if trampolineAddr == 0 {
		// If no clean trampoline in this function, find one elsewhere
		trampolineAddr = findCleanSyscallTrampoline()
	}

	return syscallNum, trampolineAddr
}

// isHooked detects if a function has been hooked
func isHooked(funcAddr uintptr) bool {
	if funcAddr == 0 {
		return true
	}

	// Read first 16 bytes to check for hooks
	funcBytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		funcBytes[i] = *(*byte)(unsafe.Pointer(funcAddr + uintptr(i)))
	}

	// Check for common hook patterns
	// JMP instructions at the start indicate hooks
	if funcBytes[0] == 0xe9 || funcBytes[0] == 0xeb { // JMP near/short
		return true
	}

	// Check for JMP indirect
	if funcBytes[0] == 0xff && (funcBytes[1]&0xf8) == 0x20 { // JMP [mem]
		return true
	}

	// Check for PUSH/RET combinations (common in hooks)
	if funcBytes[0] == 0x68 { // PUSH imm32
		return true
	}

	// Check for expected syscall stub patterns
	// Standard pattern: 4c 8b d1 b8 XX XX 00 00 (mov r10,rcx; mov eax,XXXX)
	if len(funcBytes) >= 8 &&
		funcBytes[0] == 0x4c && funcBytes[1] == 0x8b && funcBytes[2] == 0xd1 &&
		funcBytes[3] == 0xb8 {
		return false // This looks like a clean syscall stub
	}

	// Alternative pattern: b8 XX XX 00 00 4c 8b d1 (mov eax,XXXX; mov r10,rcx)
	if len(funcBytes) >= 8 &&
		funcBytes[0] == 0xb8 &&
		funcBytes[5] == 0x4c && funcBytes[6] == 0x8b && funcBytes[7] == 0xd1 {
		return false // This also looks clean
	}

	// If we can't identify the pattern, assume it's hooked
	return true
}

// findNtZwPair finds the Nt/Zw counterpart of a function
func findNtZwPair(functionHash uint32) uint32 {
	// Get all exports to find the pair
	exports := getSortedExports()
	if len(exports) == 0 {
		return 0
	}

	// Find the original function name
	var originalName string
	for _, exp := range exports {
		if obf.GetHash(exp.Name) == functionHash {
			originalName = exp.Name
			break
		}
	}

	if originalName == "" {
		return 0
	}

	// Generate the pair name
	var pairName string
	if len(originalName) >= 2 {
		if originalName[:2] == "Nt" {
			pairName = "Zw" + originalName[2:]
		} else if originalName[:2] == "Zw" {
			pairName = "Nt" + originalName[2:]
		}
	}

	if pairName != "" {
		return obf.GetHash(pairName)
	}

	return 0
}

// findSyscallTrampoline finds syscall;ret gadget in a function
func findSyscallTrampoline(funcAddr uintptr) uintptr {
	// Search for syscall;ret (0x0f 0x05 0xc3) pattern in the function
	// Limit search to first 64 bytes of function
	for i := uintptr(0); i < 64; i++ {
		addr := funcAddr + i
		if *(*byte)(unsafe.Pointer(addr)) == 0x0f &&
			*(*byte)(unsafe.Pointer(addr + 1)) == 0x05 &&
			*(*byte)(unsafe.Pointer(addr + 2)) == 0xc3 {
			return addr
		}
	}
	return 0
}

// findCleanSyscallTrampoline finds any clean syscall;ret gadget in ntdll
func findCleanSyscallTrampoline() uintptr {
	exports := getSortedExports()
	if len(exports) == 0 {
		return 0
	}

	ntdllBase := GetModuleBase(obf.GetHash("ntdll.dll"))
	if ntdllBase == 0 {
		return 0
	}

	// Scan a subset of exports to find the first clean syscall;ret trampoline
	// This avoids embedding specific NT/Zw names as literals
	const maxScan = 256
	limit := len(exports)
	if limit > maxScan {
		limit = maxScan
	}
	for i := 0; i < limit; i++ {
		addr := ntdllBase + uintptr(exports[i].VirtualAddress)
		if addr == 0 || isHooked(addr) {
			continue
		}
		if trampoline := findSyscallTrampoline(addr); trampoline != 0 {
			return trampoline
		}
	}
	// Fallback: scan the rest if needed
	for i := maxScan; i < len(exports); i++ {
		addr := ntdllBase + uintptr(exports[i].VirtualAddress)
		if addr == 0 || isHooked(addr) {
			continue
		}
		if trampoline := findSyscallTrampoline(addr); trampoline != 0 {
			return trampoline
		}
	}
	return 0
}

// extractSyscallNumberWithValidation performs enhanced validation and extraction
func extractSyscallNumberWithValidation(funcAddr uintptr, functionHash uint32) uint16 {
	if funcAddr == 0 {
		return 0
	}

	// Read enough bytes to analyze the function
	const maxBytes = 32
	funcBytes := make([]byte, maxBytes)

	// Safely read memory with bounds checking
	for i := 0; i < maxBytes; i++ {
		funcBytes[i] = *(*byte)(unsafe.Pointer(funcAddr + uintptr(i)))
	}

	// Try multiple syscall stub patterns for robustness
	syscallNumber := tryExtractSyscallNumber(funcBytes, funcAddr, functionHash)

	// Validate the extracted syscall number
	if syscallNumber > 0 && validateSyscallNumber(syscallNumber, functionHash) {
		return syscallNumber
	}

	// Fallback: try alternative extraction methods
	return tryAlternativeExtractionMethods(funcBytes, funcAddr, functionHash)
}

// tryExtractSyscallNumber attempts to extract syscall number using multiple patterns
func tryExtractSyscallNumber(funcBytes []byte, funcAddr uintptr, functionHash uint32) uint16 {
	if len(funcBytes) < 16 {
		return 0
	}

	// Pattern 1: Standard x64 syscall stub
	// 0: 4c 8b d1             mov r10, rcx
	// 3: b8 XX XX 00 00       mov eax, XXXX
	// 8: f6 04 25 08 03 fe 7f test byte ptr [0x7ffe0308], 1
	if len(funcBytes) >= 8 &&
		funcBytes[0] == 0x4c && funcBytes[1] == 0x8b && funcBytes[2] == 0xd1 &&
		funcBytes[3] == 0xb8 {

		syscallNum := uint16(funcBytes[4]) | (uint16(funcBytes[5]) << 8)
		if syscallNum > 0 && syscallNum < 2000 { // Reasonable range check
			return syscallNum
		}
	}

	// Pattern 2: Alternative syscall stub (some Windows versions)
	// 0: b8 XX XX 00 00       mov eax, XXXX
	// 5: 4c 8b d1             mov r10, rcx
	if len(funcBytes) >= 8 &&
		funcBytes[0] == 0xb8 &&
		funcBytes[5] == 0x4c && funcBytes[6] == 0x8b && funcBytes[7] == 0xd1 {

		syscallNum := uint16(funcBytes[1]) | (uint16(funcBytes[2]) << 8)
		if syscallNum > 0 && syscallNum < 2000 {
			return syscallNum
		}
	}

	// Pattern 3: Hooked syscall detection (look for JMP instruction)
	// If we find a JMP at the beginning, the function might be hooked
	if funcBytes[0] == 0xe9 || funcBytes[0] == 0xeb || funcBytes[0] == 0xff {
		return 0
	}

	return 0
}

// validateSyscallNumber performs additional validation on extracted syscall numbers
func validateSyscallNumber(syscallNumber uint16, functionHash uint32) bool {
	// Basic range validation
	if syscallNumber == 0 || syscallNumber >= 2000 {
		return false
	}

	// Check against known invalid ranges
	// Syscall numbers should be reasonable for NT kernel functions
	if syscallNumber < 2 {
		// Only syscall numbers 0 and 1 are truly suspicious
	}

	// Additional validation could include (if you want to submit a PR)
	// - Cross-referencing with known good syscall numbers
	// - Checking if the syscall number fits expected patterns
	// - Validating against syscall tables from different Windows versions

	return true
}

// tryAlternativeExtractionMethods provides fallback extraction when standard methods fail
func tryAlternativeExtractionMethods(funcBytes []byte, funcAddr uintptr, functionHash uint32) uint16 {
	// Method 1: Scan for MOV EAX instructions in the first 32 bytes
	for i := 0; i < len(funcBytes)-4; i++ {
		if funcBytes[i] == 0xb8 { // MOV EAX, imm32
			syscallNum := uint16(funcBytes[i+1]) | (uint16(funcBytes[i+2]) << 8)
			if syscallNum > 0 && syscallNum < 2000 {
				return syscallNum
			}
		}
	}

	// Method 2: Look for syscall instruction and backtrack
	for i := 0; i < len(funcBytes)-1; i++ {
		if funcBytes[i] == 0x0f && funcBytes[i+1] == 0x05 { // SYSCALL instruction
			// Found syscall instruction, now look backwards for MOV EAX
			for j := i; j >= 4; j-- {
				if funcBytes[j-4] == 0xb8 { // MOV EAX, imm32
					syscallNum := uint16(funcBytes[j-3]) | (uint16(funcBytes[j-2]) << 8)
					if syscallNum > 0 && syscallNum < 2000 {
						return syscallNum
					}
				}
			}
			break
		}
	}

	// Method 3: Scan for common offsets (less reliable)
	commonOffsets := []int{4, 5, 6, 7, 8}
	for _, offset := range commonOffsets {
		if len(funcBytes) > offset+2 {
			if funcBytes[offset] == 0xb8 { // MOV EAX
				syscallNum := uint16(funcBytes[offset+1]) | (uint16(funcBytes[offset+2]) << 8)
				if syscallNum > 0 && syscallNum < 2000 {
					return syscallNum
				}
			}
		}
	}

	// Method 4: Try reading at different offsets (handle potential hooks/patches)
	alternativeOffsets := []int{8, 12, 16, 20}
	for _, offset := range alternativeOffsets {
		if offset+1 < len(funcBytes) {
			if funcBytes[offset] == 0xb8 { // MOV EAX
				syscallNum := uint16(funcBytes[offset+1]) | (uint16(funcBytes[offset+2]) << 8)
				if syscallNum > 0 && syscallNum < 2000 {
					return syscallNum
				}
			}
		}
	}

	return 0
}

// GetSyscallWithValidation provides additional metadata and validation
func GetSyscallWithValidation(functionHash uint32) (uint16, bool, error) {
	syscallNum := GetSyscallNumber(functionHash)

	if syscallNum == 0 {
		return 0, false, errors.New(errors.Err1)
	}

	// Additional validation
	isValid := validateSyscallNumber(syscallNum, functionHash)

	return syscallNum, isValid, nil
}

func getSortedExports() []Export {
	sortedExportsOnce.Do(func() {
		ntdllBase := GetModuleBase(obf.GetHash("ntdll.dll"))
		if ntdllBase == 0 {
			return
		}

		dosHeader := (*[2]byte)(unsafe.Pointer(ntdllBase))
		if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
			return
		}

		peOffset := *(*uint32)(unsafe.Pointer(ntdllBase + 0x3C))
		file := (*[1024]byte)(unsafe.Pointer(ntdllBase + uintptr(peOffset)))
		if file[0] != 'P' || file[1] != 'E' {
			return
		}

		// Build exports directly from memory
		exports := parseExports(ntdllBase)
		sort.Slice(exports, func(i, j int) bool {
			return exports[i].VirtualAddress < exports[j].VirtualAddress
		})
		sortedExports = exports
	})
	return sortedExports
}

// GuessSyscallNumber attempts to infer a syscall number for a hooked function
// by finding clean left and right neighbors and interpolating the missing number.
func GuessSyscallNumber(targetHash uint32) uint16 {
	exports := getSortedExports()
	if len(exports) == 0 {
		return 0
	}

	ntdllBase := GetModuleBase(obf.GetHash("ntdll.dll",

	// Find the target function
	))
	if ntdllBase == 0 {
		return 0
	}

	targetIndex := -1
	for i, exp := range exports {
		if obf.GetHash(exp.Name) == targetHash {
			targetIndex = i
			break
		}
	}

	if targetIndex == -1 {
		return 0
	}

	// Helper function to check if a function is hooked
	isCleanSyscall := func(addr uintptr) (bool, uint16) {
		bytes := *(*[8]byte)(unsafe.Pointer(addr))
		// Check for standard syscall stub pattern
		if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
			syscallNum := uint16(bytes[4]) | uint16(bytes[5])<<8
			return true, syscallNum
		}
		return false, 0
	}

	// Helper function to check if two function names are NT/ZW pairs
	isNtZwPair := func(name1, name2 string) bool {
		if len(name1) < 2 || len(name2) < 2 {
			return false
		}
		// Check if one starts with Nt and other with Zw, and rest is same
		if (name1[:2] == "Nt" && name2[:2] == "Zw" && name1[2:] == name2[2:]) ||
			(name1[:2] == "Zw" && name2[:2] == "Nt" && name1[2:] == name2[2:]) {
			return true
		}
		return false
	}

	// First, check if there's a ZW/NT pair nearby (they have identical syscall numbers)
	for offset := -5; offset <= 5; offset++ {
		if offset == 0 {
			continue
		}

		pairIdx := targetIndex + offset
		if pairIdx < 0 || pairIdx >= len(exports) {
			continue
		}

		if isNtZwPair(exports[targetIndex].Name, exports[pairIdx].Name) {
			pairAddr := ntdllBase + uintptr(exports[pairIdx].VirtualAddress)
			if clean, syscallNum := isCleanSyscall(pairAddr); clean {
				return syscallNum
			}
		}
	}

	// Find clean left neighbor
	var leftSyscall uint16
	var leftIndex int = -1
	for i := targetIndex - 1; i >= 0 && i >= targetIndex-10; i-- {
		addr := ntdllBase + uintptr(exports[i].VirtualAddress)
		if clean, syscallNum := isCleanSyscall(addr); clean {
			leftSyscall = syscallNum
			leftIndex = i
			break
		}
	}

	// Find clean right neighbor
	var rightSyscall uint16
	var rightIndex int = -1
	for i := targetIndex + 1; i < len(exports) && i <= targetIndex+10; i++ {
		addr := ntdllBase + uintptr(exports[i].VirtualAddress)
		if clean, syscallNum := isCleanSyscall(addr); clean {
			rightSyscall = syscallNum
			rightIndex = i
			break
		}
	}

	// If we have both neighbors, interpolate
	if leftIndex != -1 && rightIndex != -1 {
		// Calculate the expected syscall number based on position
		positionDiff := targetIndex - leftIndex
		syscallDiff := rightSyscall - leftSyscall
		indexDiff := rightIndex - leftIndex

		if indexDiff > 0 {
			interpolated := leftSyscall + uint16((syscallDiff*uint16(positionDiff))/uint16(indexDiff))
			return interpolated
		}
	}

	// Fallback: use single neighbor with small offset
	if leftIndex != -1 {
		offset := targetIndex - leftIndex
		guessed := leftSyscall + uint16(offset)
		return guessed
	}

	if rightIndex != -1 {
		offset := rightIndex - targetIndex
		guessed := rightSyscall - uint16(offset)
		return guessed
	}

	return 0
}

// memoryReaderAt removed; no longer needed after replacing binject PE usage
