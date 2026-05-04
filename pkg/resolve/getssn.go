package resolve

import (
	"sort"
	"sync"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/obf"
)

type Syscall struct {
	Address uintptr
	SSN     uint32
}

var (
	syscallTable      map[uint32]Syscall
	syscallTableMu    sync.RWMutex
	syscallTableBuilt bool
)

func buildSyscallTable() {
	moduleBase := GetModuleBase(obf.GetHash("ntdll.dll"))
	if moduleBase == 0 {
		return
	}
	dosHeader := (*[64]byte)(unsafe.Pointer(moduleBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return
	}
	peOffset := *(*uint32)(unsafe.Pointer(moduleBase + 60))
	if peOffset >= 1024 {
		return
	}
	peHeader := (*[1024]byte)(unsafe.Pointer(moduleBase + uintptr(peOffset)))
	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		return
	}
	exportDirRVA := *(*uint32)(unsafe.Pointer(moduleBase + uintptr(peOffset) + 0x88))
	if exportDirRVA == 0 {
		return
	}
	exportDir := moduleBase + uintptr(exportDirRVA)

	numberOfNames := *(*uint32)(unsafe.Pointer(exportDir + 0x18))
	functionsRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x1C))
	namesRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x20))
	ordinalsRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x24))
	functionsAddr := moduleBase + uintptr(functionsRVA)
	namesAddr := moduleBase + uintptr(namesRVA)
	ordinalsAddr := moduleBase + uintptr(ordinalsRVA)

	type ntFunc struct {
		hash uint32
		addr uintptr
	}
	funcs := make([]ntFunc, 0, numberOfNames)

	for i := uint32(0); i < numberOfNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(namesAddr + uintptr(i*4)))
		nameAddr := moduleBase + uintptr(nameRVA)

		b0 := *(*byte)(unsafe.Pointer(nameAddr))
		b1 := *(*byte)(unsafe.Pointer(nameAddr + 1))
		if b0 != 'N' || b1 != 't' {
			continue
		}
		b2 := *(*byte)(unsafe.Pointer(nameAddr + 2))
		b3 := *(*byte)(unsafe.Pointer(nameAddr + 3))
		b4 := *(*byte)(unsafe.Pointer(nameAddr + 4))
		if b2 == 'd' && b3 == 'l' && b4 == 'l' {
			continue
		}

		ordinal := *(*uint16)(unsafe.Pointer(ordinalsAddr + uintptr(i*2)))
		funcRVA := *(*uint32)(unsafe.Pointer(functionsAddr + uintptr(ordinal*4)))
		funcAddr := moduleBase + uintptr(funcRVA)

		funcs = append(funcs, ntFunc{
			hash: obf.HashFromCString(nameAddr),
			addr: funcAddr,
		})
	}

	// sorting them gives us the ssns, thanks windows :p
	// anti hook stuff is in GetTrampoline asm implementation, thanks acheron
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].addr < funcs[j].addr
	})

	syscallTable = make(map[uint32]Syscall, len(funcs))
	for i, f := range funcs {
		syscallTable[f.hash] = Syscall{
			Address: f.addr,
			SSN:     uint32(i),
		}
	}
}

func clearSyscallTable() {
	syscallTableMu.Lock()
	syscallTable = nil
	syscallTableBuilt = false
	syscallTableMu.Unlock()
}

func GetSyscall(hash uint32) Syscall {
	syscallTableMu.RLock()
	if syscallTableBuilt {
		sc := syscallTable[hash]
		syscallTableMu.RUnlock()
		return sc
	}
	syscallTableMu.RUnlock()

	syscallTableMu.Lock()
	if !syscallTableBuilt {
		buildSyscallTable()
		syscallTableBuilt = true
	}
	sc := syscallTable[hash]
	syscallTableMu.Unlock()
	return sc
}
