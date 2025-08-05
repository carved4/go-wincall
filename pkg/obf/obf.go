package obf

import (
	"log"
	"strings"
	"sync"
	"encoding/binary"
)

var xorKey = []byte("meow-carved4-xor-key-change-if-u-want-to-use-this-in-your-own-project")

func SetXORKey(key string) {
	if len(key) == 0 {
		return 
	}
	xorKey = []byte(key)
}

func Encode(data []byte) []byte {
	encoded := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		encoded[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	return encoded
}

func Decode(encoded []byte) []byte {
	return Encode(encoded) // XOR is symmetric
}

func EncodeUintptr(ptr uintptr) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(ptr))
	return Encode(buf)
}

func DecodeUintptr(encoded []byte) uintptr {
	decoded := Decode(encoded)
	if len(decoded) < 8 {
		return 0
	}
	return uintptr(binary.LittleEndian.Uint64(decoded))
}

func DBJ2HashStr(s string) uint32 {
	return DBJ2Hash([]byte(s))
}

func DBJ2Hash(buffer []byte) uint32 {
	hash := uint32(5381)

	for _, b := range buffer {
		if b == 0 {
			continue
		}
		if b >= 'a' {
			b -= 0x20
		}

		hash = ((hash << 5) + hash) + uint32(b)
	}

	return hash
}

var HashCache = make(map[string]uint32)
var hashCacheMutex sync.RWMutex
var collisionDetector = make(map[uint32]string)
var collisionMutex sync.RWMutex

func GetHash(s string) uint32 {
	hashCacheMutex.RLock()
	if hash, ok := HashCache[s]; ok {
		hashCacheMutex.RUnlock()
		return hash
	}
	hashCacheMutex.RUnlock()

	hash := DBJ2HashStr(s)

	hashCacheMutex.Lock()
	HashCache[s] = hash
	hashCacheMutex.Unlock()

	detectHashCollision(hash, s)

	return hash
}

func detectHashCollision(hash uint32, newString string) {
	collisionMutex.Lock()
	defer collisionMutex.Unlock()
	normalizedNew := strings.ToUpper(newString)
	
	if existingString, exists := collisionDetector[hash]; exists {
		normalizedExisting := strings.ToUpper(existingString)
		if normalizedExisting != normalizedNew {
			log.Printf("Warning: Hash collision detected!")
			log.Printf("  Hash:", hash)
			log.Printf("  Existing string:", existingString)
			log.Printf("  New string:", newString)
		}
	} else {
		collisionDetector[hash] = newString
	}
}

func FNV1AHash(buffer []byte) uint32 {
	const (
		fnv1aOffset = 2166136261
		fnv1aPrime  = 16777619
	)

	hash := uint32(fnv1aOffset)

	for _, b := range buffer {
		if b == 0 {
			continue
		}

		if b >= 'a' {
			b -= 0x20
		}

		hash ^= uint32(b)
		hash *= fnv1aPrime
	}

	return hash
}

func GetHashWithAlgorithm(s string, algorithm string) uint32 {
	switch algorithm {
	case "fnv1a":
		return FNV1AHash([]byte(s))
	case "dbj2":
		fallthrough
	default:
		return DBJ2HashStr(s)
	}
}

func ClearHashCache() {
	hashCacheMutex.Lock()
	defer hashCacheMutex.Unlock()

	collisionMutex.Lock()
	defer collisionMutex.Unlock()

	HashCache = make(map[string]uint32)
	collisionDetector = make(map[uint32]string)
}

func GetHashCacheStats() map[string]interface{} {
	hashCacheMutex.RLock()
	defer hashCacheMutex.RUnlock()

	collisionMutex.RLock()
	defer collisionMutex.RUnlock()

	collisions := 0
	uniqueHashes := len(collisionDetector)
	totalEntries := len(HashCache)

	if totalEntries > uniqueHashes {
		collisions = totalEntries - uniqueHashes
	}

	return map[string]interface{}{
		"total_entries":   totalEntries,
		"unique_hashes":   uniqueHashes,
		"collisions":      collisions,
		"cache_hit_ratio": 0.0,
	}
}
