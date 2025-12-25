# go-wincall

this project is an implementation of a windows api calling convention for go. it is an expansion of concepts from `carved4/go-native-syscall`. the library provides infrastructure to interact with the windows api without importing the `syscall` package or linking against windows libraries at compile time. it is focused on the low-level mechanics of api invocation and evasion.

## demo
![output](https://github.com/user-attachments/assets/034b3151-d71d-48cd-a24a-c94fd4971a35)




## install
```bash
go get github.com/carved4/go-wincall
```


## problem: stack probing and goroutines

calling certain windows dll functions through our plan9 asm stub can result in intermittent access violation crashes, particularly when interacting with libraries compiled with msvc (e.g., `msvcrt.dll`). the root cause is a mismatch between go's stack management and the windows c runtime's expectations. many msvc-compiled functions begin with a stack probe (`_chkstk`) that requires a large, contiguous stack. go's goroutines use smaller, segmented stacks. when a dll function running on a goroutine attempts its stack probe, it accesses memory beyond the goroutine's stack limit, causing a stack overflow. using `runtime.lockosthread` is insufficient because the underlying stack is still managed by go.

## solution: g0 system stack execution

the library now executes api calls on the go runtime's system stack (g0) for the current os thread. the plan9 asm trampoline is invoked via `runtime.systemstack`, so windows `_chkstk` probes see a full native stack. there is no persistent worker thread, no shared memory, and no event signaling. arguments are prepared directly in go memory and marshaled per the windows x64 abi; results are returned directly to the caller.

### technical details

the framework avoids high-level windows apis for its setup and execution. module base addresses are found by walking the process environment block (`peb`) and its loader data structures. once a module like `ntdll.dll` is located in memory, its `pe` header is parsed to find the export address table (eat). function addresses are resolved by hashing exported function names and comparing them against a target hash, avoiding `LoadLibrary` and `GetProcAddress`. to maintain version independence, syscall numbers are not hardcoded. instead, every nt* function is parsed, their addresses are collected, and then sorted low -> high to give us their SSN. to maximize performance, the library heavily caches resolved addresses and syscall numbers. module and function addresses are cached on their first resolution, and the results of `ntdll.dll`'s export table parsing are also cached to accelerate syscall number guessing for hooked functions. the cached data is stored in an obfuscated format to deter basic memory analysis. the `UnhookNtdll()` function can restore the original `.text` section from disk to remove inline hooks.

### final binary preparation

before building your binary, run the included hash_replacer tool to remove string literals from GetHash() calls
```bash
cd tools
// change hashing algorithm in obf.go to anything you please, or keep it the same
// update hash_replacer.go hash func to match
go run hash_replacer.go

```
after building your binary, run the included strip script to remove github.com import strings:
```bash
./strip.sh your_binary.exe
```

## api usage

the library provides two main approaches for calling windows apis: a high-level convenience function and manual resolution for more control.

### high-level api

the `Call` function handles dll loading, function resolution, and execution automatically:

```go
// convert strings to utf-16 for windows apis
title, _ := wincall.UTF16ptr("high level api")
message, _ := wincall.UTF16ptr("no syscall import")

// single function call handles everything (now returns 3 values)
r1, r2, err := wincall.Call("user32.dll", "MessageBoxW",
	0, // hwnd
	uintptr(unsafe.Pointer(message)),
	uintptr(unsafe.Pointer(title)),
	0, // MB_OK
)
```

### manual resolution

for more control, manually resolve dll and function addresses:

```go
// hash dll name and get base address
dllHash := wincall.GetHash("user32.dll")
moduleBase := wincall.GetModuleBase(dllHash)

// hash function name and get address
funcHash := wincall.GetHash("MessageBoxW")
funcAddr := wincall.GetFunctionAddress(moduleBase, funcHash)

// prepare arguments
title, _ := wincall.UTF16ptr("manual")
message, _ := wincall.UTF16ptr("no syscall import")

// execute on g0 (system stack) - now returns 3 values
r1, r2, err := wincall.CallG0(
	funcAddr,
	0, // hwnd
	uintptr(unsafe.Pointer(message)),
	uintptr(unsafe.Pointer(title)),
	0, // MB_OK
)
```

### return value decoding utilities

windows apis often return packed data that requires decoding. the library provides generic utility functions for common return value patterns:

#### examples from cmd/main.go
```go
commandLinePtr, _, _ := wincall.Call("kernel32", "GetCommandLineW")
commandLine := wincall.ReadUTF16String(commandLinePtr)
fmt.Printf("command line: %s\n", commandLine)

color, _, _ := wincall.Call("user32", "GetSysColor", 5)
r := wincall.ExtractByte(color, 0)
g := wincall.ExtractByte(color, 1)
b := wincall.ExtractByte(color, 2)
fmt.Printf("window color: rgb(%d, %d, %d) = #%02X%02X%02X\n", r, g, b, r, g, b)

var buffer [260]byte
length, _, _ := wincall.Call("kernel32", "GetWindowsDirectoryA", &buffer[0], 260)
if length > 0 {
	winDir := wincall.ReadANSIString(uintptr(unsafe.Pointer(&buffer[0])))
	fmt.Printf("windows directory: %s\n", winDir)
}

title, _ := wincall.UTF16ptr("high level api")
message, _ := wincall.UTF16ptr("twitter.com/owengsmt")

wincall.Call("user32.dll", "MessageBoxW",
	0,
	message,
	title,
	0,
)
runtime.KeepAlive(title)
runtime.KeepAlive(message)
```

### available functions

#### core api functions
- `Call(dllName, funcName interface{}, args ...interface{}) (uintptr, uintptr, error)` - high-level api call
- `CallG0(funcAddr uintptr, args ...any) (uintptr, uintptr, error)` - execute function on g0 (system stack)
- `LoadLibrary(name string) uintptr` - load dll with ldrloaddll and return base address
- `UTF16ptr(s string) (*uint16, error)` - convert go string to utf-16 pointer
- `GetModuleBase(dllHash uint32) uintptr` - get module base from hash
- `GetFunctionAddress(moduleBase uintptr, funcHash uint32) uintptr` - get function address from hash
- `GetHash(s string) uint32` - get  hash for string
- `IsDebuggerPresent() bool` - check if debugger is attached to current process
- `CurrentThreadIDFast() uint32` - get current thread ID from TEB
- `RunOnG0(f func())` - run function on g0 system stack
- `ClearCache()` - clear all internal caches

#### syscall functions
- `Syscall(syscallNum uint32, args ...uintptr) (uintptr, error)` - direct system call
- `IndirectSyscall(syscallNum uint32, syscallAddr uintptr, args ...uintptr) (uintptr, error)` - indirect system call
- `GetSyscall(hash uint32) resolve.Syscall` - get syscall information (SSN and address)

#### anti-hooking and enhanced resolution functions
- `UnhookNtdll()` - restore original ntdll.dll .text section from disk, removing inline hooks

#### return value decoding utilities
- `ExtractByte(value uintptr, byteIndex int) uint8` - extract specific byte from return value
- `ExtractWord(value uintptr, wordIndex int) uint16` - extract 16-bit word from return value
- `ExtractBits(value uintptr, startBit, numBits int) uint32` - extract arbitrary bit range
- `CombineWords(low, high uint16) uint32` - combine two 16-bit words into 32-bit value
- `CombineBytes(b0, b1, b2, b3 uint8) uint32` - combine four bytes into 32-bit value
- `CombineDwords(low, high uint32) uint64` - combine two 32-bit values into 64-bit
- `SplitDwords(value uint64) (low, high uint32)` - split 64-bit value into two 32-bit parts
- `ReadUTF16String(ptr uintptr) string` - read null-terminated utf-16 string from pointer
- `ReadANSIString(ptr uintptr) string` - read null-terminated ansi string from pointer
- `ReadLARGE_INTEGER(ptr uintptr) int64` - read 64-bit value from large_integer pointer
- `ReadBytes(ptr uintptr, length int) []byte` - read byte array from memory pointer

### nt syscall wrappers

The library no longer provides specific NT syscall wrapper functions. Use manual resolution with `GetSyscall` then call syscalls:

```go
// using syscalls
syscallInfo := wincall.GetSyscall(wincall.GetHash("NtAllocateVirtualMemory"))
if syscallInfo.Address != 0 {
    // indirect syscall with anti-hook trampoline
    result, err := wincall.IndirectSyscall(syscallInfo.SSN, syscallInfo.Address, 
        processHandle,
        uintptr(unsafe.Pointer(&baseAddress)),
        zeroBits,
        uintptr(unsafe.Pointer(&regionSize)),
        allocationType,
        protect,
    )
    
    // or direct syscall
    result, err := wincall.Syscall(syscallInfo.SSN,
        processHandle,
        uintptr(unsafe.Pointer(&baseAddress)),
        zeroBits,
        uintptr(unsafe.Pointer(&regionSize)),
        allocationType,
        protect,
    )
}
```
