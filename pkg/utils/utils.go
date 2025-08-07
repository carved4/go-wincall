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
	InheritedAddressSpace      byte
	ReadImageFileExecOptions   byte
	BeingDebugged              byte
	BitField                   byte
	Mutant                     uintptr
	ImageBaseAddress           uintptr
	Ldr                        *PEB_LDR_DATA
	ProcessParameters          *RTL_USER_PROCESS_PARAMETERS
	SubSystemData              uintptr
	ProcessHeap                uintptr
	FastPebLock                uintptr
	AtlThunkSListPtr           uintptr
	IFEOKey                    uintptr
	CrossProcessFlags          uint32
	KernelCallbackTable        uintptr
	SystemReserved             uint32
	AtlThunkSListPtr32         uint32
	ApiSetMap                  uintptr
	TlsExpansionCounter        uint32
	TlsBitmap                  uintptr
	TlsBitmapBits              [2]uint32
	ReadOnlySharedMemoryBase   uintptr
	SharedData                 uintptr
	ReadOnlyStaticServerData   uintptr
	AnsiCodePageData           uintptr
	OemCodePageData            uintptr
	UnicodeCaseTableData       uintptr
	NumberOfProcessors         uint32
	NtGlobalFlag               uint32
	CriticalSectionTimeout     int64
	HeapSegmentReserve         uintptr
	HeapSegmentCommit          uintptr
	HeapDeCommitTotalFreeThreshold uintptr
	HeapDeCommitFreeBlockThreshold uintptr
	NumberOfHeaps              uint32
	MaximumNumberOfHeaps       uint32
	ProcessHeaps               uintptr
	GdiSharedHandleTable       uintptr
	ProcessStarterHelper       uintptr
	GdiDCAttributeList         uint32
	LoaderLock                 uintptr
	OSMajorVersion             uint32
	OSMinorVersion             uint32
	OSBuildNumber              uint16
	OSCSDVersion               uint16
	OSPlatformId               uint32
	ImageSubsystem             uint32
	ImageSubsystemMajorVersion uint32
	ImageSubsystemMinorVersion uint32
	ActiveProcessAffinityMask  uintptr
	GdiHandleBuffer            [60]uint32
	PostProcessInitRoutine     uintptr
	TlsExpansionBitmap         uintptr
	TlsExpansionBitmapBits     [32]uint32
	SessionId                  uint32
	AppCompatFlags             uint64
	AppCompatFlagsUser         uint64
	pShimData                  uintptr
	AppCompatInfo              uintptr
	CSDVersion                 UNICODE_STRING
	ActivationContextData      uintptr
	ProcessAssemblyStorageMap  uintptr
	SystemDefaultActivationContextData uintptr
	SystemAssemblyStorageMap   uintptr
	MinimumStackCommit         uintptr
	FlsCallback                uintptr
	FlsListHead                LIST_ENTRY
	FlsBitmap                  uintptr
	FlsBitmapBits              [4]uint32
	FlsHighIndex               uint32
	WerRegistrationData        uintptr
	WerShipAssertPtr           uintptr
	pUnused                    uintptr
	pImageHeaderHash           uintptr
	TracingFlags               uint32
	CsrServerReadOnlySharedMemoryBase uint64
	TppWorkerpListLock         uintptr
	TppWorkerpList             LIST_ENTRY
	WaitOnAddressHashTable     [128]uintptr
	TelemetryCoverageHeader    uintptr
	CloudFileFlags             uint32
	CloudFileDiagFlags         uint32
	PlaceholderCompatibilityMode byte
	PlaceholderCompatibilityModeReserved [7]byte
	LeapSecondData             uintptr
	LeapSecondFlags            uint32
	NtGlobalFlag2              uint32
}
type RTL_USER_PROCESS_PARAMETERS struct {
	MaximumLength     uint32
	Length            uint32
	Flags             uint32
	DebugFlags        uint32
	ConsoleHandle     uintptr
	ConsoleFlags      uint32
	StandardInput     uintptr
	StandardOutput    uintptr
	StandardError     uintptr
	CurrentDirectory  CURDIR
	DllPath           UNICODE_STRING
	ImagePathName     UNICODE_STRING
	CommandLine       UNICODE_STRING
	Environment       uintptr
	StartingX         uint32
	StartingY         uint32
	CountX            uint32
	CountY            uint32
	CountCharsX       uint32
	CountCharsY       uint32
	FillAttribute     uint32
	WindowFlags       uint32
	ShowWindowFlags   uint32
	WindowTitle       UNICODE_STRING
	DesktopInfo       UNICODE_STRING
	ShellInfo         UNICODE_STRING
	RuntimeData       UNICODE_STRING
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

func utf16BytesToString(b []uint16) string {
	runes := make([]rune, 0, len(b))
	for i := 0; i < len(b); i++ {
		r := rune(b[i])
		if r >= 0xD800 && r <= 0xDBFF && i+1 < len(b) {
			r2 := rune(b[i+1])
			if r2 >= 0xDC00 && r2 <= 0xDFFF {
				r = (r-0xD800)<<10 + (r2 - 0xDC00) + 0x10000
				i++
			}
		}
		runes = append(runes, r)
	}
	return string(runes)
}

func UTF16ToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}

	length := 0
	for tmp := ptr; *tmp != 0; tmp = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(tmp)) + 2)) {
		length++
	}

	slice := make([]uint16, length)
	for i := 0; i < length; i++ {
		slice[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i*2)))
	}

	return string(utf16BytesToString(slice))
}


