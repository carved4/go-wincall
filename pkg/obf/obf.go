package obf

import (
	"unsafe"
)

func Hash(buffer []byte) uint32 {
	var hash uint32 = 5381
	for _, b := range buffer {
		if b == 0 {
			continue
		}
		if b >= 'A' && b <= 'Z' {
			b = b + 0x20
		}
		hash = ((hash << 5) + hash) + uint32(b)
	}
	return hash
}

// HashFromCString hashes directly from a c string pointer without allocating a go string :3
// this eliminates the allocation that would occur from readCString + GetHash
func HashFromCString(ptr uintptr) uint32 {
	var hash uint32 = 5381
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if b == 0 {
			break
		}
		if b >= 'A' && b <= 'Z' {
			b = b + 0x20
		}
		hash = ((hash << 5) + hash) + uint32(b)
	}
	return hash
}

// HashFromCStringLen hashes from a c string pointer with known length (no null scan needed) :p
func HashFromCStringLen(ptr uintptr, length int) uint32 {
	var hash uint32 = 5381
	for i := 0; i < length; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if b == 0 {
			break
		}
		if b >= 'A' && b <= 'Z' {
			b = b + 0x20
		}
		hash = ((hash << 5) + hash) + uint32(b)
	}
	return hash
}

// HashFromUTF16 hashes directly from a null terminated utf16 string pointer :3
// this eliminates the allocation from UTF16ToString + GetHash
// dll names are ascii so we just take the low byte of each utf16 char
func HashFromUTF16(ptr uintptr) uint32 {
	var hash uint32 = 5381
	for i := uintptr(0); ; i += 2 {
		c := *(*uint16)(unsafe.Pointer(ptr + i))
		if c == 0 {
			break
		}
		// dll names are ascii, just use low byte
		b := byte(c)
		if b >= 'A' && b <= 'Z' {
			b = b + 0x20
		}
		hash = ((hash << 5) + hash) + uint32(b)
	}
	return hash
}

// HashFromUTF16Len hashes from a utf16 string with known length (in chars, not bytes) :p
func HashFromUTF16Len(ptr uintptr, charLen int) uint32 {
	var hash uint32 = 5381
	for i := 0; i < charLen; i++ {
		c := *(*uint16)(unsafe.Pointer(ptr + uintptr(i*2)))
		if c == 0 {
			break
		}
		b := byte(c)
		if b >= 'A' && b <= 'Z' {
			b = b + 0x20
		}
		hash = ((hash << 5) + hash) + uint32(b)
	}
	return hash
}

// GetHash computes hash of a string, with caching :3
// optimized to hash directly from string bytes without []byte allocation
func GetHash(s string) uint32 {
	hash := hashString(s)
	return hash
}

// hashString hashes a string without allocating a []byte copy
func hashString(s string) uint32 {
	var hash uint32 = 5381
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == 0 {
			continue
		}
		if b >= 'A' && b <= 'Z' {
			b = b + 0x20
		}
		hash = ((hash << 5) + hash) + uint32(b)
	}
	return hash
}
