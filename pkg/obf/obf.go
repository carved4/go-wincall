package obf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var (
	xorKey     []byte
	keyInitOnce sync.Once
)

func generateRuntimeKey() []byte {
	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		panic("failed keygen")
	}
	return key
}

func initXORKey() {
	keyInitOnce.Do(func() {
		xorKey = generateRuntimeKey()
	})
}

func SetXORKey(key string) {
	if len(key) == 0 {
		return 
	}
	xorKey = []byte(key)
}

func Encode(data []byte) []byte {
	initXORKey()
	encoded := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		encoded[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	return encoded
}

func Decode(encoded []byte) []byte {
	initXORKey()
	return Encode(encoded)
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

var (
	hashSeed     [32]byte
	hashInitOnce sync.Once
)

func generateHashSeed() {
	_, err := rand.Read(hashSeed[:])
	if err != nil {
		hasher := sha256.New()
		now := time.Now()
		binary.Write(hasher, binary.LittleEndian, now.UnixNano())
		binary.Write(hasher, binary.LittleEndian, now.Unix())
		binary.Write(hasher, binary.LittleEndian, uintptr(unsafe.Pointer(&hasher)))
		binary.Write(hasher, binary.LittleEndian, uintptr(unsafe.Pointer(&now)))
		binary.Write(hasher, binary.LittleEndian, uintptr(unsafe.Pointer(&hashSeed)))
		fallbackHash := hasher.Sum(nil)
		copy(hashSeed[:], fallbackHash)
	}
}

func initHashSeed() {
	hashInitOnce.Do(generateHashSeed)
}

func Hash(buffer []byte) uint32 {
	initHashSeed()
	normalized := make([]byte, len(buffer))
	for i, b := range buffer {
		if b == 0 {
			continue
		}
		if b >= 'a' && b <= 'z' {
			normalized[i] = b - 0x20
		} else {
			normalized[i] = b
		}
	}
	hasher := sha256.New()
	hasher.Write(hashSeed[:])
	hasher.Write(normalized)
	fullHash := hasher.Sum(nil)
	return binary.LittleEndian.Uint32(fullHash[:4])
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

	hash := Hash([]byte(s))

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

func GetHashWithAlgorithm(s string, algorithm string) uint32 {
	return Hash([]byte(s))
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

// ObfDecodeByte decodes obfuscated byte arrays used in string obfuscatio
func ObfDecodeByte(data []byte, key byte) string {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key ^ byte(i*3)
	}
	return string(result)
}

