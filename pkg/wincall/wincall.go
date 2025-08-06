package wincall

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/resolve"
	"github.com/carved4/go-wincall/pkg/syscall"
)

var (
	ntAllocateVirtualMemoryNum   uint16
	ntAllocateVirtualMemoryAddr  uintptr
	ntWriteVirtualMemoryNum      uint16
	ntWriteVirtualMemoryAddr     uintptr
	ntReadVirtualMemoryNum       uint16
	ntReadVirtualMemoryAddr      uintptr
	ntProtectVirtualMemoryNum    uint16
	ntProtectVirtualMemoryAddr   uintptr
	ntCreateEventNum             uint16
	ntCreateEventAddr            uintptr
	ntSetEventNum                uint16
	ntSetEventAddr               uintptr
	ntCreateThreadExNum          uint16
	ntCreateThreadExAddr         uintptr
	ntWaitForSingleObjectNum     uint16
	ntWaitForSingleObjectAddr    uintptr
	resolveSyscallsOnce          sync.Once
)

func resolveSyscalls() {
	ntAllocateVirtualMemoryNum, ntAllocateVirtualMemoryAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtAllocateVirtualMemory"))
	ntWriteVirtualMemoryNum, ntWriteVirtualMemoryAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtWriteVirtualMemory"))
	ntReadVirtualMemoryNum, ntReadVirtualMemoryAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtReadVirtualMemory"))
	ntProtectVirtualMemoryNum, ntProtectVirtualMemoryAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtProtectVirtualMemory"))
	ntCreateEventNum, ntCreateEventAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtCreateEvent"))
	ntSetEventNum, ntSetEventAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtSetEvent"))
	ntCreateThreadExNum, ntCreateThreadExAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtCreateThreadEx"))
	ntWaitForSingleObjectNum, ntWaitForSingleObjectAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtWaitForSingleObject"))
}

var taskPool = sync.Pool{
	New: func() interface{} {
		return &win32Task{
			args:       make([]uintptr, 0, maxArgs),
			argRefs:    make([]interface{}, 0, maxArgs),
			completion: make(chan taskResult, 1),
		}
	},
}

//go:noescape
func wincall_winthread_entry() uintptr

//go:noescape
func wincall_get_winthread_entry_addr() uintptr

func NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uintptr, protect uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntAllocateVirtualMemoryNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtAllocateVirtualMemory")
	}
	ret, err := syscall.IndirectSyscall(ntAllocateVirtualMemoryNum, ntAllocateVirtualMemoryAddr,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		allocationType,
		protect,
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtWriteVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer uintptr, numberOfBytesToWrite uintptr, numberOfBytesWritten *uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntWriteVirtualMemoryNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtWriteVirtualMemory")
	}
	ret, err := syscall.IndirectSyscall(ntWriteVirtualMemoryNum, ntWriteVirtualMemoryAddr,
		processHandle,
		baseAddress,
		buffer,
		numberOfBytesToWrite,
		uintptr(unsafe.Pointer(numberOfBytesWritten)),
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtReadVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer uintptr, numberOfBytesToRead uintptr, numberOfBytesRead *uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntReadVirtualMemoryNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtReadVirtualMemory")
	}
	ret, err := syscall.IndirectSyscall(ntReadVirtualMemoryNum, ntReadVirtualMemoryAddr,
		processHandle,
		baseAddress,
		buffer,
		numberOfBytesToRead,
		uintptr(unsafe.Pointer(numberOfBytesRead)),
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uintptr, oldProtect *uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntProtectVirtualMemoryNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtProtectVirtualMemory")
	}
	ret, err := syscall.IndirectSyscall(ntProtectVirtualMemoryNum, ntProtectVirtualMemoryAddr,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		newProtect,
		uintptr(unsafe.Pointer(oldProtect)),
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtCreateEvent(eventHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, eventType uintptr, initialState bool) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntCreateEventNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtCreateEvent")
	}

	var initialStateInt uintptr
	if initialState {
		initialStateInt = 1
	}

	ret, err := syscall.IndirectSyscall(ntCreateEventNum, ntCreateEventAddr,
		uintptr(unsafe.Pointer(eventHandle)),
		desiredAccess,
		objectAttributes,
		eventType,
		initialStateInt,
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtSetEvent(eventHandle uintptr, previousState *uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntSetEventNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtSetEvent")
	}
	ret, err := syscall.IndirectSyscall(ntSetEventNum, ntSetEventAddr,
		eventHandle,
		uintptr(unsafe.Pointer(previousState)),
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtCreateThreadEx(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, parameter uintptr, createFlags uintptr, stackZeroBits uintptr, stackCommitSize uintptr, stackReserveSize uintptr, attributeList uintptr) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntCreateThreadExNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtCreateThreadEx")
	}
	ret, err := syscall.IndirectSyscall(ntCreateThreadExNum, ntCreateThreadExAddr,
		uintptr(unsafe.Pointer(threadHandle)),
		desiredAccess,
		objectAttributes,
		processHandle,
		startAddress,
		parameter,
		createFlags,
		stackZeroBits,
		stackCommitSize,
		stackReserveSize,
		attributeList,
	)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func NtWaitForSingleObject(handle uintptr, alertable bool, timeout *int64) (uint32, error) {
	resolveSyscallsOnce.Do(resolveSyscalls)
	if ntWaitForSingleObjectNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtWaitForSingleObject")
	}

	var alertableFlag uintptr
	if alertable {
		alertableFlag = 1
	}

	var timeoutPtr uintptr
	if timeout != nil {
		timeoutPtr = uintptr(unsafe.Pointer(timeout))
	}

	ret, err := syscall.IndirectSyscall(ntWaitForSingleObjectNum, ntWaitForSingleObjectAddr, handle, alertableFlag, timeoutPtr)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func (w *Worker) encryptSharedMem() {
	w.sharedMemMtx.Lock()
	defer w.sharedMemMtx.Unlock()
	
	libcallData := make([]byte, libcallSize)
	var bytesRead uintptr
	status, err := NtReadVirtualMemory(
		0xFFFFFFFFFFFFFFFF, // Current process
		w.sharedMem,
		uintptr(unsafe.Pointer(&libcallData[0])),
		libcallSize,
		&bytesRead,
	)
	
	if err != nil || status != 0 || bytesRead != libcallSize {
		return
	}
	
	encryptedData := obf.Encode(libcallData)
	
	var bytesWritten uintptr
	status, err = NtWriteVirtualMemory(
		0xFFFFFFFFFFFFFFFF, // Current process
		w.sharedMem,
		uintptr(unsafe.Pointer(&encryptedData[0])),
		libcallSize,
		&bytesWritten,
	)
	
	if err != nil || status != 0 || bytesWritten != libcallSize {
		NtWriteVirtualMemory(
			0xFFFFFFFFFFFFFFFF,
			w.sharedMem,
			uintptr(unsafe.Pointer(&libcallData[0])),
			libcallSize,
			&bytesWritten,
		)
	}
}

func (w *Worker) decryptSharedMem() {
	w.sharedMemMtx.Lock()
	defer w.sharedMemMtx.Unlock()
	
	encryptedData := make([]byte, libcallSize)
	var bytesRead uintptr
	status, err := NtReadVirtualMemory(
		0xFFFFFFFFFFFFFFFF, // Current process
		w.sharedMem,
		uintptr(unsafe.Pointer(&encryptedData[0])),
		libcallSize,
		&bytesRead,
	)
	
	if err != nil || status != 0 || bytesRead != libcallSize {
		return
	}
	
	decryptedData := obf.Decode(encryptedData)
	
	var bytesWritten uintptr
	status, err = NtWriteVirtualMemory(
		0xFFFFFFFFFFFFFFFF, // Current process
		w.sharedMem,
		uintptr(unsafe.Pointer(&decryptedData[0])),
		libcallSize,
		&bytesWritten,
	)
	
	if err != nil || status != 0 || bytesWritten != libcallSize {
		// we should never get here, kill ourselves
		runtime.Goexit()
	}
}

func workerDispatcher() {
	worker := GetWorker()
	for task := range worker.tasks {
		worker.placeArgsInSharedMem(task)

		worker.decryptSharedMem()

		status, err := NtSetEvent(worker.hNewTaskEvent, nil)
		if err != nil || status != 0 {
			worker.encryptSharedMem()
			task.completion <- taskResult{0, fmt.Errorf("failed to set new task event: status=0x%x, err=%v", status, err)}
			continue
		}

		status, err = NtWaitForSingleObject(worker.hTaskDoneEvent, false, nil)
		if err != nil || status != 0 {
			worker.encryptSharedMem()
			task.completion <- taskResult{0, fmt.Errorf("failed to wait for task completion: status=0x%x, err=%v", status, err)}
			continue
		}

		result := worker.retrieveResultFromSharedMem()
		
		worker.encryptSharedMem()

		task.completion <- taskResult{result, nil}

		runtime.KeepAlive(task.argRefs)
	}
}

func Init() error {
	worker := GetWorker()
	worker.threadLock.Lock()
	defer worker.threadLock.Unlock()

	if worker.hWorkerThread != 0 {
		return nil
	}

	if err := worker.allocSharedMem(); err != nil {
		return fmt.Errorf("failed to initialize worker: %v", err)
	}

	resolveSyscallsOnce.Do(resolveSyscalls)

	status, err := NtCreateEvent(&worker.hNewTaskEvent, 0x1F0003, 0, 1, false)
	if err != nil || status != 0 {
		return fmt.Errorf("failed to create new task event: status=0x%x, err=%v", status, err)
	}

	status, err = NtCreateEvent(&worker.hTaskDoneEvent, 0x1F0003, 0, 1, false)
	if err != nil || status != 0 {
		return fmt.Errorf("failed to create task done event: status=0x%x, err=%v", status, err)
	}

	worker.waitForSingleObjectNum, worker.waitForSingleObjectAddr = ntWaitForSingleObjectNum, ntWaitForSingleObjectAddr
	worker.setEventNum, worker.setEventAddr = ntSetEventNum, ntSetEventAddr

	var threadHandle uintptr
	status, err = NtCreateThreadEx(
		&threadHandle,
		0x1FFFFF,
		0,
		0xFFFFFFFFFFFFFFFF,
		wincall_get_winthread_entry_addr(),
		uintptr(unsafe.Pointer(worker)),
		0, 0, 0, 0, 0,
	)

	if err != nil || status != 0 {
		return fmt.Errorf("failed to create worker thread: status=0x%x, err=%v", status, err)
	}
	worker.hWorkerThread = threadHandle

	go workerDispatcher()

	time.Sleep(100 * time.Millisecond)

	if err := worker.waitForWorkerReady(); err != nil {
		return fmt.Errorf("worker thread failed to initialize properly: %v", err)
	}

	return nil
}

func CallWorker(funcAddr uintptr, args ...interface{}) (uintptr, error) {
	if err := Init(); err != nil {
		return 0, err
	}
	return GetWorker().QueueTask(funcAddr, args...)
}

func (w *Worker) QueueTask(funcAddr uintptr, args ...interface{}) (uintptr, error) {
	task := taskPool.Get().(*win32Task)
	task.fn = funcAddr
	task.args = task.args[:0]
	task.argRefs = task.argRefs[:0]

	for _, arg := range args {
		task.args = append(task.args, processArg(arg))
		task.argRefs = append(task.argRefs, arg)
	}

	w.tasks <- task

	result := <-task.completion

	taskPool.Put(task)

	return result.r1, result.err
}

func (w *Worker) waitForWorkerReady() error {
	var kernel32Base uintptr
	var getCurrentProcessIdAddr uintptr

	maxRetries := 15
	for i := 0; i < maxRetries; i++ {
		kernel32Hash := obf.GetHash("kernel32.dll")
		kernel32Base = resolve.GetModuleBase(kernel32Hash)
		if kernel32Base != 0 {
			getCurrentProcessIdHash := obf.GetHash("GetCurrentProcessId")
			getCurrentProcessIdAddr = resolve.GetFunctionAddress(kernel32Base, getCurrentProcessIdHash)
			if getCurrentProcessIdAddr != 0 {
				break
			}
		}

		waitTime := time.Duration(10+i*5) * time.Millisecond
		if waitTime > 100*time.Millisecond {
			waitTime = 100 * time.Millisecond
		}
		time.Sleep(waitTime)
	}

	if kernel32Base == 0 {
		return fmt.Errorf("kernel32.dll not found during worker readiness check after %d attempts", maxRetries)
	}
	if getCurrentProcessIdAddr == 0 {
		return fmt.Errorf("GetCurrentProcessId not found during worker readiness check after %d attempts", maxRetries)
	}

	for i := 0; i < maxRetries; i++ {
		result, err := w.QueueTask(getCurrentProcessIdAddr)
		if err == nil && result != 0 {
			return nil
		}

		waitTime := time.Duration(5+i*10) * time.Millisecond
		if waitTime > 200*time.Millisecond {
			waitTime = 200 * time.Millisecond
		}
		time.Sleep(waitTime)
	}

	return fmt.Errorf("worker thread failed to respond after %d attempts", maxRetries)
}
