package wincall

import (
	"fmt"
	"unsafe"
	"github.com/carved4/go-wincall/pkg/obf"
	"github.com/carved4/go-wincall/pkg/resolve"
	"github.com/carved4/go-wincall/pkg/syscall"
)

//go:noescape
func wincall_winthread_entry() uintptr

//go:noescape
func wincall_get_winthread_entry_addr() uintptr


func NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uintptr, protect uintptr) (uint32, error) {
	syscallNum, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtAllocateVirtualMemory"))
	if syscallNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtAllocateVirtualMemory")
	}
	ret, err := syscall.IndirectSyscall(syscallNum, syscallAddr,
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
	syscallNum, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtWriteVirtualMemory"))
	if syscallNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtWriteVirtualMemory")
	}
	ret, err := syscall.IndirectSyscall(syscallNum, syscallAddr,
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
	syscallNum, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtReadVirtualMemory"))
	if syscallNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtReadVirtualMemory")
	}
	ret, err := syscall.IndirectSyscall(syscallNum, syscallAddr,
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
	syscallNum, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtProtectVirtualMemory"))
	if syscallNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtProtectVirtualMemory")
	}
	ret, err := syscall.IndirectSyscall(syscallNum, syscallAddr,
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
    syscallNum, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtCreateEvent"))
    if syscallNum == 0 {
        return 0xC0000139, fmt.Errorf("failed to resolve NtCreateEvent")
    }

    var initialStateInt uintptr
    if initialState {
        initialStateInt = 1
    }

    ret, err := syscall.IndirectSyscall(syscallNum, syscallAddr,
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
    syscallNum, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtSetEvent"))
    if syscallNum == 0 {
        return 0xC0000139, fmt.Errorf("failed to resolve NtSetEvent")
    }
    ret, err := syscall.IndirectSyscall(syscallNum, syscallAddr,
        eventHandle,
        uintptr(unsafe.Pointer(previousState)),
    )
    if err != nil {
        return uint32(ret), err
    }
    return uint32(ret), nil
}


func NtCreateThreadEx(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, parameter uintptr, createFlags uintptr, stackZeroBits uintptr, stackCommitSize uintptr, stackReserveSize uintptr, attributeList uintptr) (uint32, error) {
	syscallNum, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtCreateThreadEx"))
	if syscallNum == 0 {
		return 0xC0000139, fmt.Errorf("failed to resolve NtCreateThreadEx") 
	}
	ret, err := syscall.IndirectSyscall(syscallNum, syscallAddr,
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
	syscallNum, syscallAddr := resolve.GetSyscallAndAddress(obf.GetHash("NtWaitForSingleObject"))
	if syscallNum == 0 {
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

	ret, err := syscall.IndirectSyscall(syscallNum, syscallAddr, handle, alertableFlag, timeoutPtr)
	if err != nil {
		return uint32(ret), err
	}
	return uint32(ret), nil
}

func Init() error {
	worker := GetWorker()
	worker.threadLock.Lock()
	defer worker.threadLock.Unlock()

	// if the worker thread is already running, do nothing.
	if worker.hWorkerThread != 0 {
		return nil
	}

	// allocate shared memory for the libcall struct
	if err := worker.allocSharedMem(); err != nil {
		return fmt.Errorf("failed to initialize worker: %v", err)
	}
	
	// create synchronization events.
    // EVENT_ALL_ACCESS = 0x1F0003
    // SynchronizationEvent = 1 (auto-reset)
	status, err := NtCreateEvent(&worker.hNewTaskEvent, 0x1F0003, 0, 1, false)
	if err != nil || status != 0 {
		return fmt.Errorf("failed to create new task event: status=0x%x, err=%v", status, err)
	}

	status, err = NtCreateEvent(&worker.hTaskDoneEvent, 0x1F0003, 0, 1, false)
	if err != nil || status != 0 {
		return fmt.Errorf("failed to create task done event: status=0x%x, err=%v", status, err)
	}

	// resolve and store syscall information for the worker loop.
	worker.waitForSingleObjectNum, worker.waitForSingleObjectAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtWaitForSingleObject"))
	worker.setEventNum, worker.setEventAddr = resolve.GetSyscallAndAddress(obf.GetHash("NtSetEvent"))


	var threadHandle uintptr
	status, err = NtCreateThreadEx(
		&threadHandle,
		0x1FFFFF,                          // THREAD_ALL_ACCESS
		0,
		0xFFFFFFFFFFFFFFFF,                // Current process
		wincall_get_winthread_entry_addr(), // Start address
		uintptr(unsafe.Pointer(worker)),   // Pass the worker struct to the thread
		0, 0, 0, 0, 0,
	)

	if err != nil || status != 0 {
		return fmt.Errorf("failed to create worker thread: status=0x%x, err=%v", status, err)
	}
	worker.hWorkerThread = threadHandle
	return nil
}

// CallInNewThread is now a wrapper around the worker queue.
func CallWorker(funcAddr uintptr, args ...uintptr) (uintptr, error) {
	if err := Init(); err != nil {
		return 0, err
	}
	return GetWorker().QueueTask(funcAddr, args...)
}

// QueueTask sends a task to the worker and waits for its completion.
func (w *Worker) QueueTask(funcAddr uintptr, args ...uintptr) (uintptr, error) {
	// lock the worker to prevent race conditions on shared memory.
	// this ensures only one API call can be "in flight" at any given time.
	w.Lock()
	defer w.Unlock()

	task := &win32Task{
		fn:         funcAddr,
		args:       args,
		completion: make(chan uintptr, 1),
	}
	
	w.placeArgsInSharedMem(task)
	
	// signal the worker thread that there is a new task.
	status, err := NtSetEvent(w.hNewTaskEvent, nil)
	if err != nil || status != 0 {
		return 0, fmt.Errorf("failed to set new task event: status=0x%x, err=%v", status, err)
	}

	// wait for the worker to complete the task.
	status, err = NtWaitForSingleObject(w.hTaskDoneEvent, false, nil)
	if err != nil || status != 0 {
		return 0, fmt.Errorf("failed to wait for task completion: status=0x%x, err=%v", status, err)
	}

	result := w.retrieveResultFromSharedMem()
	return result, nil
}
