# go-wincall

this project is an implementation of a windows api calling convention for go. it is an expansion of concepts from `carved4/go-native-syscall`. the library provides infrastructure to interact with the windows api without importing the `syscall` package or linking against windows libraries at compile time. it is focused on the low-level mechanics of api invocation and does not include capabilities beyond that scope.

## demo
![demo3](https://github.com/user-attachments/assets/6e5cfeb5-4eb7-46ec-b93c-0b0a324bb605)



## install
```bash
go get github.com/carved4/go-wincall
```
>it is still recommended to import runtime/debug and debug.SetGCPercent(-1) first in main()

## problem: stack probing and goroutines

calling certain windows dll functions through our plan9 asm stub can result in intermittent access violation crashes, particularly when interacting with libraries compiled with msvc (e.g., `msvcrt.dll`). the root cause is a mismatch between go's stack management and the windows c runtime's expectations. many msvc-compiled functions begin with a stack probe (`_chkstk`) that requires a large, contiguous stack. go's goroutines use smaller, segmented stacks. when a dll function running on a goroutine attempts its stack probe, it accesses memory beyond the goroutine's stack limit, causing a stack overflow. using `runtime.lockosthread` is insufficient because the underlying stack is still managed by go.

## solution: persistent native thread execution

the implemented solution bypasses go's thread and stack management for api calls using a single, persistent native windows thread. an indirect syscall to `ntcreatethreadex` creates one native windows thread during initialization. this os-level thread is initialized with a full-sized stack that satisfies the `_chkstk` probe and runs an infinite event loop waiting for api call requests. when a call is needed, the target function and its arguments are passed to this persistent worker thread via shared memory and event signaling. the result is retrieved after execution and synchronized back to the calling goroutine. this ensures all calls operate in an environment with a native stack while maintaining massive efficiency gains over the previous one-thread-per-call model.

### technical Details

the framework avoids high-level Windows APIs for its setup and execution. module base addresses are found by walking the Process Environment Block (`PEB`) and its loader data structures. once a module like `ntdll.dll` is located in memory, its `PE` header is parsed to find the Export Address Table (EAT). function addresses are resolved by hashing exported function names and comparing them against a target hash, avoiding `LoadLibrary` and `GetProcAddress`. to maintain version independence, syscall numbers are not hardcoded. instead, the prologue of the target syscall function (e.g., `NtCreateThreadEx`) is read to dynamically extract the syscall number from the `MOV EAX, <SSN>` instruction. to maximize performance, the library heavily caches resolved addresses and syscall numbers. module and function addresses are cached on their first resolution, and the results of `ntdll.dll`'s export table parsing are also cached to accelerate syscall number guessing for hooked functions. the cached data is stored in an obfuscated format to deter basic memory analysis. all necessary syscalls for the `Nt*` wrapper functions are pre-resolved once and reused for all subsequent calls, eliminating redundant lookups. the persistent worker thread is created via an indirect syscall to `NtCreateThreadEx` during the first API call. the worker runs an assembly loop that waits on `NtWaitForSingleObject` for task events. when a task arrives, it reads the `libcall` struct from shared memory (allocated via `NtAllocateVirtualMemory`), executes the call using a `stdcall` assembly trampoline, writes the result back to shared memory, and signals completion via `NtSetEvent`. arguments are copied to stable memory to prevent corruption from Go's stack management, and task objects are recycled using a `sync.Pool` to reduce garbage collector overhead. the main Go program waits for completion via `NtWaitForSingleObject` before retrieving the return value. mutex synchronization ensures thread-safe access to the shared memory block.

## api usage

the library provides two main approaches for calling windows apis: a high-level convenience function and manual resolution for more control.

### high-level api

the `Call` function handles dll loading, function resolution, and execution automatically:

```go
// convert strings to utf-16 for windows apis
title, _ := wincall.UTF16ptr("high level api")
message, _ := wincall.UTF16ptr("no syscall import")

// single function call handles everything
wincall.Call("user32.dll", "MessageBoxW",
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

// execute in persistent native thread
wincall.CallWorker(
	funcAddr,
	0, // hwnd
	uintptr(unsafe.Pointer(message)),
	uintptr(unsafe.Pointer(title)),
	0, // MB_OK
)
```

### return value decoding utilities

windows apis often return packed data that requires decoding. the library provides generic utility functions for common return value patterns:

#### packed numeric data
```go
// get system window background color
color, _ := wincall.Call("user32", "GetSysColor", 5)

// extract RGB components from packed color value
r := wincall.ExtractByte(color, 0)  // red component (0-255)
g := wincall.ExtractByte(color, 1)  // green component (0-255)  
b := wincall.ExtractByte(color, 2)  // blue component (0-255)

fmt.Printf("window color: rgb(%d, %d, %d) = #%02X%02X%02X\n", r, g, b, r, g, b)
```

#### string pointers
```go
// get command line as utf-16 string pointer
commandLinePtr, _ := wincall.Call("kernel32", "GetCommandLineW")

// decode utf-16 string from pointer
commandLine := wincall.ReadUTF16String(commandLinePtr)
fmt.Printf("command line: %s\n", commandLine)
```

#### bit field extraction
```go
// extract arbitrary bit ranges from any return value
packedValue := uintptr(0x12345678)

valueType := wincall.ExtractBits(packedValue, 0, 4)   // bits 0-3
subtype := wincall.ExtractBits(packedValue, 4, 4)     // bits 4-7  
id := wincall.ExtractBits(packedValue, 8, 8)          // bits 8-15
data := wincall.ExtractBits(packedValue, 16, 16)      // bits 16-31
```

### available functions

#### core api functions
- `Call(dllName, funcName string, args ...uintptr) (uintptr, error)` - high-level api call
- `CallWorker(funcAddr uintptr, args ...uintptr) (uintptr, error)` - execute function in persistent native thread
- `LoadLibraryW(dllName string) uintptr` - load dll and return base address
- `GetProcAddress(moduleHandle uintptr, procName *byte) uintptr` - get function address (procName must be a null-terminated string pointer)
- `UTF16ptr(s string) (*uint16, error)` - convert go string to utf-16 pointer
- `GetModuleBase(dllHash uint32) uintptr` - get module base from hash
- `GetFunctionAddress(moduleBase uintptr, funcHash uint32) uintptr` - get function address from hash
- `GetHash(s string) uint32` - generate djb2 hash for string

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

#### nt syscall wrappers
- `NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uintptr, protect uintptr) (uint32, error)` - allocates memory in a target process.
- `NtWriteVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer uintptr, numberOfBytesToWrite uintptr, numberOfBytesWritten *uintptr) (uint32, error)` - writes to memory in a target process.
- `NtReadVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer uintptr, numberOfBytesToRead uintptr, numberOfBytesRead *uintptr) (uint32, error)` -reads memory from a target process.
- `NtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uintptr, oldProtect *uintptr) (uint32, error)` - changes protection on a memory region.
- `NtCreateEvent(eventHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, eventType uintptr, initialState bool) (uint32, error)` - creates a kernel event object.
- `NtSetEvent(eventHandle uintptr, previousState *uintptr) (uint32, error)`  Sets (signals) a kernel event.
- `NtCreateThreadEx(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, parameter uintptr, createFlags uintptr, stackZeroBits uintptr, stackCommitSize uintptr, stackReserveSize uintptr, attributeList uintptr) (uint32, error)` - creates a native Windows thread
- `NtWaitForSingleObject(handle uintptr, alertable bool, timeout *int64) (uint32, error)` - waits on a kernel object.

> **note**  
> unlike the previous architecture, all calls now use a single persistent worker thread. this provides massive performance and opsec improvements over spawning individual threads per call.
> "single thread" in this context doesnt mean our PID has one thread, as go runtime spawns multiple threads on init, this is unavoidable
> however, every winapi call made though this library will be under the same thread :)
