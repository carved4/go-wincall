package resolve

import (
	"debug/pe"
	"os"
	"runtime"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/errors"
	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/syscall"
)

func UnhookNtdll() error {
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllHandle := GetModuleBase(ntdllHash)
	if ntdllHandle == 0 {
		return errors.New(errors.Err1)
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}
	cleanNtdllPath := systemRoot + "\\System32\\ntdll.dll"

	cleanPE, err := pe.Open(cleanNtdllPath)
	if err != nil {
		return errors.New(errors.Err1)
	}
	defer cleanPE.Close()

	var textSection *pe.Section
	for _, section := range cleanPE.Sections {
		if section.Name == ".text" {
			textSection = section
			break
		}
	}
	if textSection == nil {
		return errors.New(errors.Err1)
	}
	cleanTextData, err := textSection.Data()
	if err != nil {
		return errors.New(errors.Err1)
	}
	targetAddr := ntdllHandle + uintptr(textSection.VirtualAddress)
	textSize := uintptr(len(cleanTextData))
	maxSize := uintptr(textSection.Size)
	if textSize > maxSize {
		textSize = maxSize
	}
	currentProcess := uintptr(0xffffffffffffffff)

	var oldProtect uintptr

	ntProtectHash := obf.GetHash("NtProtectVirtualMemory")
	syscallNum := GetSyscall(ntProtectHash)
	if syscallNum.Address == 0 {
		return errors.New(errors.Err1)
	}

	trampoline := syscall.GetTrampoline(syscallNum.Address)

	result, err := syscall.IndirectSyscall(syscallNum.SSN, trampoline,
		currentProcess,
		uintptr(unsafe.Pointer(&targetAddr)),
		uintptr(unsafe.Pointer(&textSize)),
		0x40, // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	status := uint32(result)
	if err != nil {
		return errors.New(errors.Err1)
	}

	if status != 0 {
		return errors.New(errors.Err1)
	}

	if len(cleanTextData) == 0 {
		return errors.New(errors.Err1)
	}
	sourceAddr := uintptr(unsafe.Pointer(&cleanTextData[0]))
	runtime.KeepAlive(cleanTextData)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(targetAddr)), int(textSize))
	src := unsafe.Slice((*byte)(unsafe.Pointer(sourceAddr)), int(textSize))
	copy(dst, src)
	runtime.KeepAlive(cleanTextData)

	var dummy uintptr
	result2, err := syscall.IndirectSyscall(syscallNum.SSN, trampoline,
		currentProcess,
		uintptr(unsafe.Pointer(&targetAddr)),
		uintptr(unsafe.Pointer(&textSize)),
		oldProtect,
		uintptr(unsafe.Pointer(&dummy)),
	)
	status2 := uint32(result2)
	if err != nil || status2 != 0 {
		return errors.New(errors.Err1)
	}
	ClearResolveCaches()
	return nil
}
