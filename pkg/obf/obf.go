package obf

import (
	"log"
	"strings"
	"sync"
	"encoding/binary"
	"time"
	"unsafe"
	"crypto/sha256"
	"crypto/rand"
	"os"
	"runtime"
)

var (
	xorKey     []byte
	keyInitOnce sync.Once
)

// this is now cryptographically secure 
func generateRuntimeKey() []byte {
	key := make([]byte, 64)
	n, err := rand.Read(key)
	if err != nil || n != len(key) {
		now := time.Now()
		seed := uint64(now.UnixNano())
		
		seed ^= uint64(now.Unix()) << 32
		seed ^= uint64(now.Nanosecond()) << 16
		seed ^= uint64(uintptr(unsafe.Pointer(&seed)))
		seed ^= uint64(uintptr(unsafe.Pointer(&now)))
		seed ^= uint64(os.Getpid()) << 24
		seed ^= uint64(runtime.NumGoroutine()) << 8
		
		for i := 0; i < len(key); i++ {
			seed = seed*1103515245 + 12345
			key[i] = byte(seed >> 16)
		}
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
	hashSeed     uint64
	hashInitOnce sync.Once
)

func generateHashSeed() {
	seedBytes := make([]byte, 8)
	n, err := rand.Read(seedBytes)
	if err == nil && n == 8 {
		hashSeed = binary.LittleEndian.Uint64(seedBytes)
	} else {
		now := time.Now()
		seed := uint64(now.UnixNano())
		seed ^= uint64(now.Unix()) << 32
		seed ^= uint64(now.Nanosecond()) << 16
		seed ^= uint64(uintptr(unsafe.Pointer(&seed)))
		seed ^= uint64(uintptr(unsafe.Pointer(&now)))
		hashSeed = seed
	}
	hashSeed ^= uint64(os.Getpid()) << 24
	hashSeed ^= uint64(runtime.NumGoroutine()) << 8
	var stackVar int
	hashSeed ^= uint64(uintptr(unsafe.Pointer(&stackVar))) >> 3
	mem := make([]byte, 1)
	hashSeed ^= uint64(uintptr(unsafe.Pointer(&mem[0]))) >> 4
}

func initHashSeed() {
	hashInitOnce.Do(generateHashSeed)
}

func sha256Hash(buffer []byte) uint32 {
	initHashSeed()
	hasher := sha256.New()
	seedBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seedBytes, hashSeed)
	hasher.Write(seedBytes)
	runtimeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(runtimeBytes, uint64(time.Now().UnixNano()))
	hasher.Write(runtimeBytes)
	pidBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pidBytes, uint32(os.Getpid()))
	hasher.Write(pidBytes)
	upperBuffer := make([]byte, len(buffer))
	for i, b := range buffer {
		if b >= 'a' && b <= 'z' {
			upperBuffer[i] = b - 0x20
		} else {
			upperBuffer[i] = b
		}
	}
	hasher.Write(upperBuffer)
	hash := hasher.Sum(nil)
	return binary.LittleEndian.Uint32(hash[:4])
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

	hash := sha256Hash([]byte(s))

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
			log.Printf("  Hash: %d", hash)
			log.Printf("  Existing string: %s", existingString)
			log.Printf("  New string: %s", newString)
		}
	} else {
		collisionDetector[hash] = newString
	}
}

func GetHashWithAlgorithm(s string, algorithm string) uint32 {
	return sha256Hash([]byte(s))
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

