package main

import (
	"fmt"
	"runtime/debug"
	"unicode/utf16"
	"unsafe"
	"github.com/carved4/go-wincall"
)

func main() {
	// disable gc to prevent collection of utf16 string buffers
	debug.SetGCPercent(-1)

	fmt.Println("=== Testing wincall High-Level API ===")

	// Test functions with no arguments
	testGetCurrentProcessId()
	testGetCurrentThreadId()

	// Test functions with arguments
	testSleep()
	testGetModuleHandleW()
	testLoadLibraryW()
	testGetSystemMetrics()
	testGetWindowsDirectoryW()
	testGetSystemDirectoryW()

	// Test error handling
	testErrorHandling()

	// Test multiple calls stability
	testMultipleCallsStability()

	fmt.Println("\n=== All tests completed ===")
}

// testGetCurrentProcessId tests a function with no arguments returning DWORD
func testGetCurrentProcessId() {
	fmt.Print("Testing GetCurrentProcessId... ")
	
	// Test manual resolution and call
	dllHash := wincall.GetHash("kernel32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)
	funcHash := wincall.GetHash("GetCurrentProcessId")
	funcAddr := wincall.GetFunctionAddress(moduleBase, funcHash)
	
	if funcAddr == 0 {
		fmt.Printf("FAILED: could not resolve GetCurrentProcessId address\n")
		return
	}
	
	// Manual call
	manualResult, manualErr := wincall.CallInNewThread(funcAddr)
	fmt.Printf("\n  Manual call result: %d, err: %v\n", manualResult, manualErr)
	
	// High-level call
	result, err := wincall.Call("kernel32.dll", "GetCurrentProcessId")
	if err != nil {
		fmt.Printf("  High-level call FAILED: %v\n", err)
		return
	}
	fmt.Printf("  High-level call result: %d\n", result)
	
	if result == 0 {
		fmt.Printf("FAILED: high-level call returned 0, expected non-zero PID\n")
		return
	}
	fmt.Printf("PASSED: PID = %d\n", result)
}

// testGetCurrentThreadId tests a function with no arguments returning DWORD
func testGetCurrentThreadId() {
	fmt.Print("Testing GetCurrentThreadId... ")
	result, err := wincall.Call("kernel32.dll", "GetCurrentThreadId")
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	if result == 0 {
		fmt.Printf("FAILED: returned 0, expected non-zero TID\n")
		return
	}
	fmt.Printf("PASSED: TID = %d\n", result)
}

// testSleep tests a function with one argument
func testSleep() {
	fmt.Print("Testing Sleep... ")
	_, err := wincall.Call("kernel32.dll", "Sleep", 1) // sleep for 1ms
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	fmt.Printf("PASSED: Sleep(1) completed\n")
}

// testGetModuleHandleW tests a function with one pointer argument
func testGetModuleHandleW() {
	fmt.Print("Testing GetModuleHandleW... ")
	// Test with NULL (current module)
	result, err := wincall.Call("kernel32.dll", "GetModuleHandleW", 0)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	if result == 0 {
		fmt.Printf("FAILED: returned 0, expected module handle\n")
		return
	}
	fmt.Printf("PASSED: handle = 0x%x\n", result)

	// Test with specific module name
	kernel32Name, _ := wincall.UTF16ptr("kernel32.dll")
	result2, err := wincall.Call("kernel32.dll", "GetModuleHandleW", 
		uintptr(unsafe.Pointer(kernel32Name)))
	if err != nil {
		fmt.Printf("FAILED (kernel32.dll): %v\n", err)
		return
	}
	if result2 == 0 {
		fmt.Printf("FAILED: kernel32.dll returned 0\n")
		return
	}
	fmt.Printf("PASSED: kernel32.dll handle = 0x%x\n", result2)
}

// testLoadLibraryW tests a function with one string argument
func testLoadLibraryW() {
	fmt.Print("Testing LoadLibraryW... ")
	dllName, _ := wincall.UTF16ptr("user32.dll")
	result, err := wincall.Call("kernel32.dll", "LoadLibraryW", 
		uintptr(unsafe.Pointer(dllName)))
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	if result == 0 {
		fmt.Printf("FAILED: returned 0, expected module handle\n")
		return
	}
	fmt.Printf("PASSED: user32.dll loaded at 0x%x\n", result)
}

// testGetSystemMetrics tests a function with one integer argument
func testGetSystemMetrics() {
	fmt.Print("Testing GetSystemMetrics... ")
	// SM_CXSCREEN = 0 (screen width)
	width, err := wincall.Call("user32.dll", "GetSystemMetrics", 0)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	if width == 0 {
		fmt.Printf("FAILED: screen width returned 0\n")
		return
	}

	// SM_CYSCREEN = 1 (screen height)
	height, err := wincall.Call("user32.dll", "GetSystemMetrics", 1)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	if height == 0 {
		fmt.Printf("FAILED: screen height returned 0\n")
		return
	}
	fmt.Printf("PASSED: screen %dx%d\n", width, height)
}

// testGetWindowsDirectoryW tests a function with two arguments (buffer + size)
func testGetWindowsDirectoryW() {
	fmt.Print("Testing GetWindowsDirectoryW... ")
	buffer := make([]uint16, 260) // MAX_PATH
	result, err := wincall.Call("kernel32.dll", "GetWindowsDirectoryW",
		uintptr(unsafe.Pointer(&buffer[0])),
		260)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	if result == 0 {
		fmt.Printf("FAILED: returned 0, expected path length\n")
		return
	}
	
	// Convert UTF-16 buffer to string for display
	windowsDir := UTF16ToString(buffer[:result])
	fmt.Printf("PASSED: %s (length: %d)\n", windowsDir, result)
}

// testGetSystemDirectoryW tests a function with two arguments (buffer + size)
func testGetSystemDirectoryW() {
	fmt.Print("Testing GetSystemDirectoryW... ")
	buffer := make([]uint16, 260) // MAX_PATH
	result, err := wincall.Call("kernel32.dll", "GetSystemDirectoryW",
		uintptr(unsafe.Pointer(&buffer[0])),
		260)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	if result == 0 {
		fmt.Printf("FAILED: returned 0, expected path length\n")
		return
	}
	
	// Convert UTF-16 buffer to string for display
	systemDir := UTF16ToString(buffer[:result])
	fmt.Printf("PASSED: %s (length: %d)\n", systemDir, result)
}

// Helper function to convert UTF-16 slice to Go string
func UTF16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			s = s[:i]
			break
		}
	}
	return string(utf16.Decode(s))
}

// testErrorHandling tests error handling with invalid function
func testErrorHandling() {
	fmt.Print("Testing error handling... ")
	_, err := wincall.Call("nonexistent.dll", "NonExistentFunction")
	if err == nil {
		fmt.Printf("FAILED: expected error for nonexistent DLL\n")
		return
	}
	fmt.Printf("PASSED: correctly handled error: %v\n", err)
}

// testMultipleCallsStability tests multiple sequential calls
func testMultipleCallsStability() {
	fmt.Print("Testing multiple calls stability... ")
	for i := 0; i < 5; i++ {
		result, err := wincall.Call("kernel32.dll", "GetCurrentProcessId")
		if err != nil {
			fmt.Printf("FAILED: call %d failed: %v\n", i, err)
			return
		}
		if result == 0 {
			fmt.Printf("FAILED: call %d returned 0\n", i)
			return
		}
	}
	fmt.Printf("PASSED: 5 consecutive calls successful\n")
}