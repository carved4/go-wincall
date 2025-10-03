package obf

import (
	"sync"
)

var (
	hashCache      = make(map[string]uint32)
	hashCacheMutex sync.RWMutex
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

func GetHash(s string) uint32 {
	hashCacheMutex.RLock()
	if hash, ok := hashCache[s]; ok {
		hashCacheMutex.RUnlock()
		return hash
	}
	hashCacheMutex.RUnlock()

	hash := Hash([]byte(s))

	hashCacheMutex.Lock()
	hashCache[s] = hash
	hashCacheMutex.Unlock()

	return hash
}

func ClearHashCache() {
	hashCacheMutex.Lock()
	defer hashCacheMutex.Unlock()
	hashCache = make(map[string]uint32)
}
