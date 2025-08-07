package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func main() {
	var projectDir string
	var reverseMode bool
	
	if len(os.Args) < 2 {
		// Try to auto-detect project root
		var err error
		projectDir, err = findProjectRoot()
		if err != nil {
			fmt.Println("usage: go run obfuscate.go [project_directory] or go run obfuscate.go to auto-detect project root")
			fmt.Println("       go run obfuscate.go --reverse [project_directory] to reverse obfuscation")
			fmt.Println("this tool scans for GetHash(\"string\") patterns, \"Nt*\" strings, and wincall.Call() calls and obfuscates them")
			fmt.Println("")
			fmt.Printf("Error auto-detecting project root: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf(" project root: %s\n", projectDir)
	} else if os.Args[1] == "--reverse" {
		reverseMode = true
		if len(os.Args) < 3 {
			var err error
			projectDir, err = findProjectRoot()
			if err != nil {
				fmt.Printf("Error auto-detecting project root: %v\n", err)
				os.Exit(1)
			}
		} else {
			projectDir = os.Args[2]
		}
		fmt.Printf("Reverse mode: restoring original strings in %s\n", projectDir)
	} else {
		projectDir = os.Args[1]
	}
	
	// Generate master seed for this run
	masterSeed := generateMasterSeed()
	fmt.Printf("Generated master seed: %x\n", masterSeed[:8])
	
	// Find all .go files
	goFiles, err := findGoFiles(projectDir)
	if err != nil {
		fmt.Printf("error finding Go files: %v\n", err)
		os.Exit(1)
	}
	
	totalReplacements := 0
	
	for _, file := range goFiles {
		var count int
		var err error
		
		if reverseMode {
			count, err = reverseObfuscation(file)
		} else {
			count, err = processFile(file, masterSeed)
		}
		
		if err != nil {
			fmt.Printf("error processing %s: %v\n", file, err)
			continue
		}
		if count > 0 {
			if reverseMode {
				fmt.Printf("restored %d strings in %s\n", count, file)
			} else {
				fmt.Printf("obfuscated %d strings in %s\n", count, file)
			}
			totalReplacements += count
		}
	}
	
	if totalReplacements == 0 {
		if reverseMode {
			fmt.Println("no obfuscated strings found to restore")
		} else {
			fmt.Println("no strings found to obfuscate")
		}
	} else {
		if reverseMode {
			fmt.Printf("successfully restored %d strings across %d files\n", totalReplacements, len(goFiles))
			fmt.Println("original strings have been restored!")
		} else {
			fmt.Printf("successfully obfuscated %d strings across %d files\n", totalReplacements, len(goFiles))
			fmt.Println("your project is ready to build with obfuscated strings!")
			fmt.Println("")
			fmt.Println("[!!!] IMPORTANT: add this import to files that use obfuscated strings:")
			fmt.Println("   \"github.com/carved4/go-wincall/pkg/obf\"")
		}
	}
}

func generateMasterSeed() []byte {
	seed := make([]byte, 32)
	
	// Combine time and crypto random
	timeBytes := make([]byte, 8)
	now := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		timeBytes[i] = byte(now >> (i * 8))
	}
	
	randBytes := make([]byte, 24)
	rand.Read(randBytes)
	
	copy(seed[:8], timeBytes)
	copy(seed[8:], randBytes)
	
	// Hash it for better distribution
	hash := sha256.Sum256(seed)
	return hash[:]
}

func findGoFiles(dir string) ([]string, error) {
	var goFiles []string
	
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip vendor, .git, and other common directories
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
		}
		
		if strings.HasSuffix(path, ".go") && !strings.Contains(path, "_test.go") {
			goFiles = append(goFiles, path)
		}
		
		return nil
	})
	
	return goFiles, err
}

func processFile(filename string, masterSeed []byte) (int, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	
	newContent := string(content)
	totalReplacements := 0
	
	// Find GetHash("string") patterns
	getHashRe := regexp.MustCompile(`GetHash\("([^"]+)"\)`)
	getHashMatches := getHashRe.FindAllStringSubmatch(string(content), -1)
	
	for _, match := range getHashMatches {
		fullMatch := match[0]      // GetHash("string")
		stringLiteral := match[1]  // string
		
		// Generate unique obfuscation for this string
		obfuscated := obfuscateString(stringLiteral, masterSeed)
		
		// Replace GetHash("string") with GetHash(obf.ObfDecodeByte(...))
		replacement := fmt.Sprintf("GetHash(%s)", obfuscated)
		newContent = strings.Replace(newContent, fullMatch, replacement, 1)
		totalReplacements++
	}
	
	// Find standalone Nt* string literals
	ntRe := regexp.MustCompile(`"(Nt[A-Za-z0-9_]+)"`)
	ntMatches := ntRe.FindAllStringSubmatch(newContent, -1)
	
	for _, match := range ntMatches {
		fullMatch := match[0]      // "NtFunction"
		stringLiteral := match[1]  // NtFunction
		
		// Generate unique obfuscation for this string
		obfuscated := obfuscateString(stringLiteral, masterSeed)
		
		// Replace "NtFunction" with obf.ObfDecodeByte(...)
		newContent = strings.Replace(newContent, fullMatch, obfuscated, 1)
		totalReplacements++
	}
	
	// Find wincall.Call("dllName", "funcName", ...) patterns
	callRe := regexp.MustCompile(`wincall\.Call\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*([^)]*)\)`)
	callMatches := callRe.FindAllStringSubmatch(newContent, -1)
	
	for _, match := range callMatches {
		fullMatch := match[0]      // wincall.Call("dllName", "funcName", args...)
		dllName := match[1]        // dllName
		funcName := match[2]       // funcName
		restArgs := match[3]       // , args... (could be empty)
		
		// Generate obfuscations for both strings
		obfDllName := obfuscateString(dllName, masterSeed)
		obfFuncName := obfuscateString(funcName, masterSeed)
		
		// Replace with obfuscated version
		var replacement string
		if strings.TrimSpace(restArgs) == "" {
			replacement = fmt.Sprintf("wincall.Call(%s, %s)", obfDllName, obfFuncName)
		} else {
			replacement = fmt.Sprintf("wincall.Call(%s, %s%s)", obfDllName, obfFuncName, restArgs)
		}
		newContent = strings.Replace(newContent, fullMatch, replacement, 1)
		totalReplacements += 2 // Count both strings
	}
	
	// FindCall("dllName", "funcName", ...) patterns (without wincall prefix)
	callShortRe := regexp.MustCompile(`(?:^|\s)Call\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*([^)]*)\)`)
	callShortMatches := callShortRe.FindAllStringSubmatch(newContent, -1)
	
	for _, match := range callShortMatches {
		fullMatch := match[0]      //Call("dllName", "funcName", args...)
		dllName := match[1]        // dllName
		funcName := match[2]       // funcName
		restArgs := match[3]       // , args... (could be empty)
		
		// Generate obfuscations for both strings
		obfDllName := obfuscateString(dllName, masterSeed)
		obfFuncName := obfuscateString(funcName, masterSeed)
		
		// Replace with obfuscated version  
		var replacement string
		if strings.TrimSpace(restArgs) == "" {
			replacement = fmt.Sprintf("Call(%s, %s)", obfDllName, obfFuncName)
		} else {
			replacement = fmt.Sprintf("Call(%s, %s%s)", obfDllName, obfFuncName, restArgs)
		}
		newContent = strings.Replace(newContent, fullMatch, replacement, 1)
		totalReplacements += 2 // Count both strings
	}
	
	// Note: Files using obfuscated strings will need to import:
	// "github.com/carved4/go-wincall/pkg/obf"
	
	// Write the modified content back
	err = ioutil.WriteFile(filename, []byte(newContent), 0644)
	if err != nil {
		return 0, err
	}
	
	return totalReplacements, nil
}

func obfuscateString(s string, masterSeed []byte) string {
	// Create string-specific key from master seed + string hash
	stringHash := sha256.Sum256([]byte(s))
	key := masterSeed[0] ^ stringHash[0] ^ byte(len(s))
	
	// XOR obfuscate the string
	obfuscated := make([]byte, len(s))
	for i, b := range []byte(s) {
		obfuscated[i] = byte(b) ^ key ^ byte(i*3)
	}
	
	// Format as byte array literal
	var byteParts []string
	for _, b := range obfuscated {
		byteParts = append(byteParts, fmt.Sprintf("0x%02x", b))
	}
	
	return fmt.Sprintf("obf.ObfDecodeByte([]byte{%s}, 0x%02x)", 
		strings.Join(byteParts, ", "), key)
}

func findProjectRoot() (string, error) {
	// Start from current directory
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %v", err)
	}
	
	// Look for go.mod file walking up the directory tree
	dir := currentDir
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}
		
		// Check if we've reached the root
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	
	// If no go.mod found, look for other indicators
	dir = currentDir
	for {
		// Check for common project indicators
		indicators := []string{".git", "README.md", "main.go"}
		for _, indicator := range indicators {
			indicatorPath := filepath.Join(dir, indicator)
			if _, err := os.Stat(indicatorPath); err == nil {
				return dir, nil
			}
		}
		
		// Check if we've reached the root
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	
	// Fall back to current directory
	return currentDir, nil
}

// reverseObfuscation restores original strings from obfuscated ones
func reverseObfuscation(filename string) (int, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	
	newContent := string(content)
	totalRestorations := 0
	
	// Find GetHash(obf.ObfDecodeByte(...)) patterns
	getHashObfRe := regexp.MustCompile(`GetHash\(obf\.ObfDecodeByte\(\[\]byte\{([^}]+)\},\s*0x([0-9a-fA-F]+)\)\)`)
	getHashObfMatches := getHashObfRe.FindAllStringSubmatch(newContent, -1)
	
	for _, match := range getHashObfMatches {
		fullMatch := match[0]       // GetHash("str")
		byteString := match[1]      // 0x6c, 0x68, 0x6b
		keyString := match[2]       // 1f
		
		// Decode the obfuscated string
		original, err := decodeObfuscatedString(byteString, keyString)
		if err != nil {
			continue // Skip if we can't decode
		}
		
		// Replace with original string
		replacement := fmt.Sprintf(`GetHash("%s")`, original)
		newContent = strings.Replace(newContent, fullMatch, replacement, 1)
		totalRestorations++
	}
	
	// Find standalone obf.ObfDecodeByte(...) patterns
	obfDecodeRe := regexp.MustCompile(`obf\.ObfDecodeByte\(\[\]byte\{([^}]+)\},\s*0x([0-9a-fA-F]+)\)`)
	obfDecodeMatches := obfDecodeRe.FindAllStringSubmatch(newContent, -1)
	
	for _, match := range obfDecodeMatches {
		fullMatch := match[0]       // "NtF"
		byteString := match[1]      // 0x46, 0x7f, 0x48
		keyString := match[2]       // 08
		
		// Decode the obfuscated string
		original, err := decodeObfuscatedString(byteString, keyString)
		if err != nil {
			continue // Skip if we can't decode
		}
		
		// Replace with original string
		replacement := fmt.Sprintf(`"%s"`, original)
		newContent = strings.Replace(newContent, fullMatch, replacement, 1)
		totalRestorations++
	}
	
	// Find wincall.Call(obf.ObfDecodeByte(...), obf.ObfDecodeByte(...), ...) patterns
	callObfRe := regexp.MustCompile(`wincall\.Call\(obf\.ObfDecodeByte\(\[\]byte\{([^}]+)\},\s*0x([0-9a-fA-F]+)\),\s*obf\.ObfDecodeByte\(\[\]byte\{([^}]+)\},\s*0x([0-9a-fA-F]+)\)([^)]*)\)`)
	callObfMatches := callObfRe.FindAllStringSubmatch(newContent, -1)
	
	for _, match := range callObfMatches {
		fullMatch := match[0]       // wincall.Call(obf.ObfDecodeByte(...), obf.ObfDecodeByte(...), ...)
		dllByteString := match[1]   // dll name bytes
		dllKeyString := match[2]    // dll key
		funcByteString := match[3]  // func name bytes
		funcKeyString := match[4]   // func key
		restArgs := match[5]        // remaining args
		
		// Decode both strings
		dllName, err1 := decodeObfuscatedString(dllByteString, dllKeyString)
		funcName, err2 := decodeObfuscatedString(funcByteString, funcKeyString)
		
		if err1 != nil || err2 != nil {
			continue // Skip if we can't decode
		}
		
		// Replace with original strings
		var replacement string
		if strings.TrimSpace(restArgs) == "" {
			replacement = fmt.Sprintf(`wincall.Call("%s", "%s")`, dllName, funcName)
		} else {
			replacement = fmt.Sprintf(`wincall.Call("%s", "%s"%s)`, dllName, funcName, restArgs)
		}
		newContent = strings.Replace(newContent, fullMatch, replacement, 1)
		totalRestorations += 2 // Count both strings
	}
	
	// Find Call(obf.ObfDecodeByte(...), obf.ObfDecodeByte(...), ...) patterns (without wincall prefix)
	callShortObfRe := regexp.MustCompile(`(?:^|\s)Call\(obf\.ObfDecodeByte\(\[\]byte\{([^}]+)\},\s*0x([0-9a-fA-F]+)\),\s*obf\.ObfDecodeByte\(\[\]byte\{([^}]+)\},\s*0x([0-9a-fA-F]+)\)([^)]*)\)`)
	callShortObfMatches := callShortObfRe.FindAllStringSubmatch(newContent, -1)
	
	for _, match := range callShortObfMatches {
		fullMatch := match[0]       // Call(obf.ObfDecodeByte(...), obf.ObfDecodeByte(...), ...)
		dllByteString := match[1]   // dll name bytes
		dllKeyString := match[2]    // dll key
		funcByteString := match[3]  // func name bytes
		funcKeyString := match[4]   // func key
		restArgs := match[5]        // remaining args
		
		// Decode both strings
		dllName, err1 := decodeObfuscatedString(dllByteString, dllKeyString)
		funcName, err2 := decodeObfuscatedString(funcByteString, funcKeyString)
		
		if err1 != nil || err2 != nil {
			continue // Skip if we can't decode
		}
		
		// Replace with original strings
		var replacement string
		if strings.TrimSpace(restArgs) == "" {
			replacement = fmt.Sprintf(`Call("%s", "%s")`, dllName, funcName)
		} else {
			replacement = fmt.Sprintf(`Call("%s", "%s"%s)`, dllName, funcName, restArgs)
		}
		newContent = strings.Replace(newContent, fullMatch, replacement, 1)
		totalRestorations += 2 // Count both strings
	}
	
	// Write the modified content back if any changes were made
	if totalRestorations > 0 {
		err = ioutil.WriteFile(filename, []byte(newContent), 0644)
		if err != nil {
			return 0, err
		}
	}
	
	return totalRestorations, nil
}

// decodeObfuscatedString decodes an obfuscated byte array back to the original string
func decodeObfuscatedString(byteString, keyString string) (string, error) {
	// Parse the key
	key, err := parseHexByte(keyString)
	if err != nil {
		return "", err
	}
	
	// Parse the byte array
	bytes, err := parseByteArray(byteString)
	if err != nil {
		return "", err
	}
	
	// Decode using the same algorithm as the obfuscation
	result := make([]byte, len(bytes))
	for i, b := range bytes {
		result[i] = b ^ key ^ byte(i*3)
	}
	
	return string(result), nil
}

// parseHexByte parses a hex string to a byte
func parseHexByte(hexStr string) (byte, error) {
	var val byte
	_, err := fmt.Sscanf(hexStr, "%x", &val)
	return val, err
}

// parseByteArray parses a string like "0x6c, 0x68, 0x6b" to []byte
func parseByteArray(byteStr string) ([]byte, error) {
	parts := strings.Split(byteStr, ",")
	result := make([]byte, len(parts))
	
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "0x") {
			return nil, fmt.Errorf("invalid hex format: %s", part)
		}
		
		var val byte
		_, err := fmt.Sscanf(part, "0x%x", &val)
		if err != nil {
			return nil, err
		}
		result[i] = val
	}
	
	return result, nil
}
