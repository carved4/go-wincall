package resolve

import (
    "unsafe"
)

// Export represents a single exported symbol from a PE image
type Export struct {
    Name            string
    VirtualAddress  uint32
    Ordinal         uint32
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

