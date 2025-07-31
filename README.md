# go-wincall

this project is an implementation of a windows api calling convention for go. it is an expansion of concepts from `carved4/go-native-syscall`. the library provides infrastructure to interact with the windows api without importing the `syscall` package or linking against windows libraries at compile time. it is focused on the low-level mechanics of api invocation and does not include capabilities beyond that scope.

## demo
![demo (3)](https://github.com/user-attachments/assets/0786f2db-043b-4b1e-8af2-da8f651c2864)

## install
```bash
go get github.com/carved4/go-wincall
```

## note 
always import runtime/debug and call debug.SetGCPercent(-1) to stop gc from collecting our utf16ptrfromstring buffers, fuck u google

## problem: stack probing and goroutines

calling certain windows dll functions through our plan9 asm stub can result in intermittent access violation crashes, particularly when interacting with libraries compiled with msvc (e.g., `msvcrt.dll`). the root cause is a mismatch between go's stack management and the windows c runtime's expectations. many msvc-compiled functions begin with a stack probe (`_chkstk`) that requires a large, contiguous stack. go's goroutines use smaller, segmented stacks. when a dll function running on a goroutine attempts its stack probe, it accesses memory beyond the goroutine's stack limit, causing a stack overflow. using `runtime.lockosthread` is insufficient because the underlying stack is still managed by go.

## solution: native thread execution

the implemented solution bypasses go's thread and stack management for the api call. a direct syscall to `ntcreatethreadex` creates a new, native windows thread. this os-level thread is initialized with a full-sized stack that satisfies the `_chkstk` probe. the target function and its arguments are passed to this new thread for execution. the result is retrieved after the thread completes and is synchronized via an indirect syscall to `ntwaitforsingleobject`. this ensures the call operates in an environment with a native stack.

### technical details

the framework avoids high-level windows apis for its setup and execution. module base addresses are found by walking the process environment block (`peb`) and its loader data structures. once a module like `ntdll.dll` is located in memory, its `pe` header is parsed to find the export address table (eat). function addresses are resolved by hashing exported function names and comparing them against a target hash, avoiding `loadlibrary` and `getprocaddress`. to maintain version independence, syscall numbers are not hardcoded. instead, the prologue of the target syscall function (e.g., `ntcreatethreadex`) is read to dynamically extract the syscall number from the `mov eax, <ssn>` instruction. the api call is performed in a new native thread created via an indirect syscall to `ntcreatethreadex`. a pointer to a `libcall` struct, containing the target function's address and arguments, is passed to the thread. an assembly entry point, `wincall_winthread_entry`, unpacks this struct and executes the call using a `stdcall` assembly trampoline. the main go program waits for completion via an indirect syscall to `ntwaitforsingleobject` before retrieving the return value.


## api usage

the library provides two main approaches for calling windows apis: a high-level convenience function and manual resolution for more control.

### setup

first, import the necessary packages and disable garbage collection to prevent collection of utf-16 string buffers:

```go
import (
	"unsafe"
	"github.com/carved4/go-wincall"
	"runtime/debug"
)

func main() {
	// disable gc to prevent collection of utf16 string or similar buffers we need throughout
	debug.SetGCPercent(-1)}
```

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

// execute in new native thread
wincall.CallInNewThread(
	funcAddr,
	0, // hwnd
	uintptr(unsafe.Pointer(message)),
	uintptr(unsafe.Pointer(title)),
	0, // MB_OK
)
```

### available functions

- `Call(dllName, funcName string, args ...uintptr)` - high-level api call
- `CallInNewThread(funcAddr uintptr, args ...uintptr)` - execute function in native thread
- `LoadLibraryW(dllName string)` - load dll and return base address
- `GetProcAddress(moduleBase uintptr, funcName string)` - get function address
- `UTF16ptr(s string)` - convert go string to utf-16 pointer
- `GetModuleBase(dllHash uint32)` - get module base from hash
- `GetFunctionAddress(moduleBase uintptr, funcHash uint32)` - get function address from hash
- `GetHash(s string)` - generate djb2 hash for string

