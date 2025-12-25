package utils

import "unsafe"

type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           LIST_ENTRY
	InMemoryOrderLinks         LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uintptr
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint32
	SsHandle                        uintptr
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
}

type PEB struct {
	InheritedAddressSpace                byte
	ReadImageFileExecOptions             byte
	BeingDebugged                        byte
	BitField                             byte
	Mutant                               uintptr
	ImageBaseAddress                     uintptr
	Ldr                                  *PEB_LDR_DATA
	ProcessParameters                    *RTL_USER_PROCESS_PARAMETERS
	SubSystemData                        uintptr
	ProcessHeap                          uintptr
	FastPebLock                          uintptr
	AtlThunkSListPtr                     uintptr
	IFEOKey                              uintptr
	CrossProcessFlags                    uint32
	KernelCallbackTable                  uintptr
	SystemReserved                       uint32
	AtlThunkSListPtr32                   uint32
	ApiSetMap                            uintptr
	TlsExpansionCounter                  uint32
	TlsBitmap                            uintptr
	TlsBitmapBits                        [2]uint32
	ReadOnlySharedMemoryBase             uintptr
	SharedData                           uintptr
	ReadOnlyStaticServerData             uintptr
	AnsiCodePageData                     uintptr
	OemCodePageData                      uintptr
	UnicodeCaseTableData                 uintptr
	NumberOfProcessors                   uint32
	NtGlobalFlag                         uint32
	CriticalSectionTimeout               int64
	HeapSegmentReserve                   uintptr
	HeapSegmentCommit                    uintptr
	HeapDeCommitTotalFreeThreshold       uintptr
	HeapDeCommitFreeBlockThreshold       uintptr
	NumberOfHeaps                        uint32
	MaximumNumberOfHeaps                 uint32
	ProcessHeaps                         uintptr
	GdiSharedHandleTable                 uintptr
	ProcessStarterHelper                 uintptr
	GdiDCAttributeList                   uint32
	LoaderLock                           uintptr
	OSMajorVersion                       uint32
	OSMinorVersion                       uint32
	OSBuildNumber                        uint16
	OSCSDVersion                         uint16
	OSPlatformId                         uint32
	ImageSubsystem                       uint32
	ImageSubsystemMajorVersion           uint32
	ImageSubsystemMinorVersion           uint32
	ActiveProcessAffinityMask            uintptr
	GdiHandleBuffer                      [60]uint32
	PostProcessInitRoutine               uintptr
	TlsExpansionBitmap                   uintptr
	TlsExpansionBitmapBits               [32]uint32
	SessionId                            uint32
	AppCompatFlags                       uint64
	AppCompatFlagsUser                   uint64
	pShimData                            uintptr
	AppCompatInfo                        uintptr
	CSDVersion                           UNICODE_STRING
	ActivationContextData                uintptr
	ProcessAssemblyStorageMap            uintptr
	SystemDefaultActivationContextData   uintptr
	SystemAssemblyStorageMap             uintptr
	MinimumStackCommit                   uintptr
	FlsCallback                          uintptr
	FlsListHead                          LIST_ENTRY
	FlsBitmap                            uintptr
	FlsBitmapBits                        [4]uint32
	FlsHighIndex                         uint32
	WerRegistrationData                  uintptr
	WerShipAssertPtr                     uintptr
	pUnused                              uintptr
	pImageHeaderHash                     uintptr
	TracingFlags                         uint32
	CsrServerReadOnlySharedMemoryBase    uint64
	TppWorkerpListLock                   uintptr
	TppWorkerpList                       LIST_ENTRY
	WaitOnAddressHashTable               [128]uintptr
	TelemetryCoverageHeader              uintptr
	CloudFileFlags                       uint32
	CloudFileDiagFlags                   uint32
	PlaceholderCompatibilityMode         byte
	PlaceholderCompatibilityModeReserved [7]byte
	LeapSecondData                       uintptr
	LeapSecondFlags                      uint32
	NtGlobalFlag2                        uint32
}
type RTL_USER_PROCESS_PARAMETERS struct {
	MaximumLength      uint32
	Length             uint32
	Flags              uint32
	DebugFlags         uint32
	ConsoleHandle      uintptr
	ConsoleFlags       uint32
	StandardInput      uintptr
	StandardOutput     uintptr
	StandardError      uintptr
	CurrentDirectory   CURDIR
	DllPath            UNICODE_STRING
	ImagePathName      UNICODE_STRING
	CommandLine        UNICODE_STRING
	Environment        uintptr
	StartingX          uint32
	StartingY          uint32
	CountX             uint32
	CountY             uint32
	CountCharsX        uint32
	CountCharsY        uint32
	FillAttribute      uint32
	WindowFlags        uint32
	ShowWindowFlags    uint32
	WindowTitle        UNICODE_STRING
	DesktopInfo        UNICODE_STRING
	ShellInfo          UNICODE_STRING
	RuntimeData        UNICODE_STRING
	CurrentDirectories [32]RTL_DRIVE_LETTER_CURDIR
}

type RTL_DRIVE_LETTER_CURDIR struct {
	Flags     uint16
	Length    uint16
	TimeStamp uint32
	DosPath   UNICODE_STRING
}

type CURDIR struct {
	DosPath UNICODE_STRING
	Handle  uintptr
}

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   uint32
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}
type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32

	DataDirectory [16]IMAGE_DATA_DIRECTORY
}
type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

// UTF16ToString converts a null terminated utf16 string to a go string :3
// optimized to minimize allocations: directly builds utf8 bytes without
// intermediate rune slice or utf16 slice copy
func UTF16ToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}

	// first pass: count utf16 chars and estimate utf8 length
	length := 0
	utf8Len := 0
	for tmp := uintptr(unsafe.Pointer(ptr)); ; {
		c := *(*uint16)(unsafe.Pointer(tmp))
		if c == 0 {
			break
		}
		length++
		// estimate utf8 bytes needed
		if c < 0x80 {
			utf8Len++
		} else if c < 0x800 {
			utf8Len += 2
		} else if c >= 0xD800 && c <= 0xDBFF {
			// high surrogate, will combine with low surrogate for 4 byte sequence
			utf8Len += 4
		} else if c >= 0xDC00 && c <= 0xDFFF {
			// low surrogate, already counted with high surrogate
		} else {
			utf8Len += 3
		}
		tmp += 2
	}

	if length == 0 {
		return ""
	}

	// single allocation for result :p
	buf := make([]byte, 0, utf8Len)
	base := uintptr(unsafe.Pointer(ptr))

	for i := 0; i < length; i++ {
		c := *(*uint16)(unsafe.Pointer(base + uintptr(i*2)))
		if c == 0 {
			break
		}

		// handle surrogate pairs
		if c >= 0xD800 && c <= 0xDBFF && i+1 < length {
			c2 := *(*uint16)(unsafe.Pointer(base + uintptr((i+1)*2)))
			if c2 >= 0xDC00 && c2 <= 0xDFFF {
				// decode surrogate pair to rune
				r := rune(c-0xD800)<<10 + rune(c2-0xDC00) + 0x10000
				// encode as 4 byte utf8
				buf = append(buf,
					byte(0xF0|(r>>18)),
					byte(0x80|((r>>12)&0x3F)),
					byte(0x80|((r>>6)&0x3F)),
					byte(0x80|(r&0x3F)))
				i++ // skip low surrogate
				continue
			}
		}

		// regular bmp character
		if c < 0x80 {
			buf = append(buf, byte(c))
		} else if c < 0x800 {
			buf = append(buf, byte(0xC0|(c>>6)), byte(0x80|(c&0x3F)))
		} else {
			buf = append(buf, byte(0xE0|(c>>12)), byte(0x80|((c>>6)&0x3F)), byte(0x80|(c&0x3F)))
		}
	}

	return string(buf)
}
