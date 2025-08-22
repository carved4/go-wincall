package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"	
	"strings"
	"runtime"
	"unsafe"	
	"github.com/carved4/go-wincall"
)

	
func main() {
	wincall.UnhookNtdll()
	if wincall.IsDebuggerPresent() {
		os.Exit(1)
	}
	fmt.Println("go-wincall demo :3")
	showMenu()
}

func showMenu() {
	scanner := bufio.NewScanner(os.Stdin)
	
	for {
		fmt.Println("\nchoose an option:")
		fmt.Println("1. custom dll/function resolver")
		fmt.Println("2. run messagebox examples")
		fmt.Println("3. exit")
		fmt.Print("\nenter choice (1-3): ")
		
		if !scanner.Scan() {
			break
		}
		
		choice := strings.TrimSpace(scanner.Text())
		
		switch choice {
		case "1":
			customResolver(scanner)
		case "2":
			runExamples()
		case "3":
			fmt.Println("goodbye!")
			return
		default:
			fmt.Println("invalid choice. please enter 1, 2, or 3.")
		}
	}
}

func customResolver(scanner *bufio.Scanner) {
	fmt.Println("\n--- custom dll/function resolver ---")
	
	for {
		fmt.Print("enter dll name (e.g., kernel32.dll) or 'back' to return: ")
		if !scanner.Scan() {
			return
		}
		
		dllName := strings.TrimSpace(scanner.Text())
		if strings.ToLower(dllName) == "back" {
			return
		}
		
		if dllName == "" {
			fmt.Println("please enter a dll name.")
			continue
		}
		
		fmt.Print("enter function name, ordinal number, or leave empty for first export: ")
		if !scanner.Scan() {
			return
		}
		
		funcInput := strings.TrimSpace(scanner.Text())
		
		fmt.Printf("\nloading %s...\n", dllName)
		wincall.LoadLibraryW(dllName)
		nativeThreadId, goThreadId, _ := wincall.GetWorkerThreadIds()
		fmt.Printf("native thread id: %d\n", nativeThreadId)
		fmt.Printf("go thread id: %d\n", goThreadId)

		dllHash := wincall.GetHash(dllName)
		moduleBase := wincall.GetModuleBase(dllHash)
		
		if moduleBase == 0 {
			fmt.Printf("error: could not load %s\n", dllName)
			continue
		}
		
		var funcAddr uintptr
		var resolveType string
		var resolveName string
		
		if funcInput == "" {
			funcAddr = wincall.GetFunctionAddress(moduleBase, 1)
			resolveType = "first export"
			resolveName = "ordinal #1"
		} else {
			if ordinal, err := strconv.Atoi(funcInput); err == nil && ordinal > 0 {
				funcAddr = wincall.GetFunctionAddress(moduleBase, uint32(ordinal))
				resolveType = "ordinal"
				resolveName = fmt.Sprintf("ordinal #%d", ordinal)
			} else {
				funcHash := wincall.GetHash(funcInput)
				funcAddr = wincall.GetFunctionAddress(moduleBase, funcHash)
				resolveType = "function name"
				resolveName = funcInput
			}
		}
		
		if funcAddr == 0 {
			fmt.Printf("error: could not resolve %s in %s\n", resolveName, dllName)
			continue
		}
		
		fmt.Printf("success!\n")
		fmt.Printf("  %s loaded at: 0x%x\n", dllName, moduleBase)
		fmt.Printf("  %s (%s) resolved to: 0x%x\n", resolveName, resolveType, funcAddr)
		
		fmt.Print("\nwould you like to resolve another function? (y/n): ")
		if !scanner.Scan() {
			return
		}
		
		if strings.ToLower(strings.TrimSpace(scanner.Text())) != "y" {
			return
		}
	}
}

func runExamples() {
	exampleHighLevel()
	exampleManual()
	fmt.Println("examples completed!")	
}

// high level api usage :3
func exampleHighLevel() {
	commandLinePtr, _ := wincall.Call("kernel32", "GetCommandLineW")
	commandLine := wincall.ReadUTF16String(commandLinePtr)
	fmt.Printf("command line: %s\n", commandLine)

	color, _ := wincall.Call("user32", "GetSysColor", 5)
	r := wincall.ExtractByte(color, 0)
	g := wincall.ExtractByte(color, 1)
	b := wincall.ExtractByte(color, 2)
	fmt.Printf("window color: rgb(%d, %d, %d) = #%02X%02X%02X\n", r, g, b, r, g, b)

	var buffer [260]byte
	length, _ := wincall.Call("kernel32", "GetWindowsDirectoryA", &buffer[0], 260)
	if length > 0 {
		winDir := wincall.ReadANSIString(uintptr(unsafe.Pointer(&buffer[0])))
		fmt.Printf("windows directory: %s\n", winDir)
	}

	title, _ := wincall.UTF16ptr("high level api")
	message, _ := wincall.UTF16ptr("twitter.com/owengsmt")

	wincall.Call("user32.dll", "MessageBoxW",
		0, // hwnd
		message,
		title,
		0, // MB_OK
	)
	runtime.KeepAlive(title)
	runtime.KeepAlive(message)
}

// manual usage
func exampleManual() {
	wincall.LoadLibraryW("user32.dll")
	dllHash := wincall.GetHash("user32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)

	funcHash := wincall.GetHash("MessageBoxW")
	funcAddr := wincall.GetFunctionAddress(moduleBase, funcHash)

	title, _ := wincall.UTF16ptr("manual")
	message, _ := wincall.UTF16ptr("twitter.com/owengsmt")

	wincall.CallWorker(
		funcAddr,
		0, // hwnd
		message,
		title,
		0, // MB_OK
	)
	runtime.KeepAlive(title)
	runtime.KeepAlive(message)
}