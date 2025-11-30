package resolve

import (
	"sort"
	"strings"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/obf"
)

type Syscall struct {
	Address uintptr
	SSN     uint32
}

func GetSyscall(hash uint32) Syscall {
	moduleBase := GetModuleBase(obf.GetHash("ntdll.dll"))
	if moduleBase == 0 {
		return Syscall{}
	}
	dosHeader := (*[64]byte)(unsafe.Pointer(moduleBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return Syscall{}
	}
	peOffset := *(*uint32)(unsafe.Pointer(moduleBase + 60))
	if peOffset >= 1024 {
		return Syscall{}
	}
	peHeader := (*[1024]byte)(unsafe.Pointer(moduleBase + uintptr(peOffset)))
	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		return Syscall{}
	}
	exportDirRVA := *(*uint32)(unsafe.Pointer(moduleBase + uintptr(peOffset) + 0x88))
	if exportDirRVA == 0 {
		return Syscall{}
	}
	exportDir := moduleBase + uintptr(exportDirRVA)

	numberOfNames := *(*uint32)(unsafe.Pointer(exportDir + 0x18))
	functionsRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x1C))
	namesRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x20))
	ordinalsRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x24))
	functionsAddr := moduleBase + uintptr(functionsRVA)
	namesAddr := moduleBase + uintptr(namesRVA)
	ordinalsAddr := moduleBase + uintptr(ordinalsRVA)
	syscalls := make([]Syscall, 0, numberOfNames)
	var targetAddr uintptr

	for i := uint32(0); i < numberOfNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(namesAddr + uintptr(i*4)))
		nameAddr := moduleBase + uintptr(nameRVA)
		nameString := cString(nameAddr)

		nameHash := obf.GetHash(nameString)

		if strings.HasPrefix(nameString, "Nt") {
			ordinal := *(*uint16)(unsafe.Pointer(ordinalsAddr + uintptr(i*2)))
			funcRVA := *(*uint32)(unsafe.Pointer(functionsAddr + uintptr(ordinal*4)))
			funcAddr := moduleBase + uintptr(funcRVA)

			syscalls = append(syscalls, Syscall{
				Address: funcAddr,
			})

			if nameHash == hash {
				targetAddr = funcAddr
			}
		}
	}
	if targetAddr == 0 {
		return Syscall{}
	}
	// sorting them gives us the ssns, thanks windows
	// anti hook stuff is in GetTrampoline asm implementation, thanks acheron
	sort.Slice(syscalls, func(i, j int) bool {
		return syscalls[i].Address < syscalls[j].Address
	})

	for i, sc := range syscalls {
		if sc.Address == targetAddr {
			return Syscall{
				Address: targetAddr,
				SSN:     uint32(i) - 4, // hack: subtract the functions that have nt* in name but aren't syscalls
			}
		}
	}

	return Syscall{}
}

func cString(addr uintptr) string {
	if addr == 0 {
		return ""
	}
	length := 0
	for {
		c := *(*byte)(unsafe.Pointer(addr + uintptr(length)))
		if c == 0 {
			break
		}
		length++
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(addr)), length))
}
