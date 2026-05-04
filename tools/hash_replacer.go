package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func computeHash(s string) uint32 {
	var hash uint32 = 5381
	for _, b := range []byte(s) {
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

func processFile(path string, dryRun bool) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	original := string(content)
	modified := original
	pattern := regexp.MustCompile(`(\w+\.)?GetHash\("([^"]+)"\)`)

	stats.filesScanned++
	matches := pattern.FindAllStringSubmatch(original, -1)
	if len(matches) == 0 {
		return nil
	}

	fmt.Printf("\n%s:\n", path)

	replacements := make(map[string]string)

	for _, match := range matches {
		fullMatch := match[0]
		stringLiteral := match[2]

		hash := computeHash(stringLiteral)
		replacement := fmt.Sprintf("uint32(0x%08X)", hash)

		if _, exists := replacements[fullMatch]; !exists {
			replacements[fullMatch] = replacement
			fmt.Printf("  %s -> %s  // \"%s\"\n", fullMatch, replacement, stringLiteral)
		}
	}

	for old, new := range replacements {
		modified = strings.ReplaceAll(modified, old, new)
	}

	stats.replacements += len(replacements)
	if modified != original {
		stats.filesModified++
		if !dryRun {
			return os.WriteFile(path, []byte(modified), 0644)
		}
	}

	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: go run hash_replacer.go [--dry-run] <project-path>\n")
	os.Exit(1)
}

var stats struct {
	filesScanned  int
	filesModified int
	replacements  int
}

func main() {
	var dryRun bool
	var root string

	args := os.Args[1:]
	for _, a := range args {
		switch {
		case a == "--dry-run":
			dryRun = true
		case strings.HasPrefix(a, "-"):
			usage()
		default:
			if root != "" {
				usage()
			}
			root = a
		}
	}
	if root == "" {
		usage()
	}

	if dryRun {
		fmt.Println("DRY RUN MODE - No files will be modified")
	}
	fmt.Printf("Scanning directory: %s\n", root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		return processFile(path, dryRun)
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nScanned %d files, %d replacements in %d files.\n", stats.filesScanned, stats.replacements, stats.filesModified)
	if dryRun {
		fmt.Println("Dry run complete. Run without --dry-run to apply changes.")
	} else {
		fmt.Println("Done.")
	}
}
