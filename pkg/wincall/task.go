package wincall

import (
	"fmt"
	"sync"
	"unsafe"
)

type win32Task struct {
	fn         uintptr
	args       []uintptr
	r1         uintptr
	completion chan uintptr
}

// worker manages the persistent native worker thread and the task queue.
type Worker struct {
	sync.Mutex
	tasks          chan *win32Task
	threadLock     sync.Mutex
	hWorkerThread  uintptr
	hNewTaskEvent  uintptr
	hTaskDoneEvent uintptr
	sharedMem      uintptr
	argsBuffer     uintptr
	sharedMemMtx   sync.Mutex

	waitForSingleObjectAddr uintptr
	waitForSingleObjectNum  uint16
	setEventAddr            uintptr
	setEventNum             uint16
}

var w *Worker
var once sync.Once

func (w *Worker) Get() *win32Task {
	task := <-w.tasks
	return task
}

func (w *Worker) Set(task *win32Task, r1 uintptr) {
	task.completion <- r1
}

// getter methods for debugging
func (w *Worker) HNewTaskEvent() uintptr { return w.hNewTaskEvent }
func (w *Worker) HTaskDoneEvent() uintptr { return w.hTaskDoneEvent }
func (w *Worker) SharedMem() uintptr { return w.sharedMem }
func (w *Worker) WaitAddr() uintptr { return w.waitForSingleObjectAddr }
func (w *Worker) WaitNum() uint16 { return w.waitForSingleObjectNum }
func (w *Worker) SetAddr() uintptr { return w.setEventAddr }
func (w *Worker) SetNum() uint16 { return w.setEventNum }

func newWorker() *Worker {
	return &Worker{
		tasks: make(chan *win32Task, 1),
	}
}

func GetWorker() *Worker {
	once.Do(func() {
		w = newWorker()
	})
	return w
}

const libcallSize = 48
const maxArgs = 16
const argsBufferSize = maxArgs * 8  // 16 args * 8 bytes each = 128 bytes

func (w *Worker) allocSharedMem() error {
	w.sharedMemMtx.Lock()
	defer w.sharedMemMtx.Unlock()

	if w.sharedMem != 0 {
		return nil
	}

	var baseAddress uintptr
	// allocate space for both libcall struct and arguments buffer
	regionSize := uintptr(libcallSize + argsBufferSize)
	// MEM_COMMIT | MEM_RESERVE = 0x3000
	// PAGE_READWRITE = 0x04
	status, err := NtAllocateVirtualMemory(0xFFFFFFFFFFFFFFFF, &baseAddress, 0, &regionSize, 0x3000, 0x04)
	if err != nil || status != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed for worker shared memory: status=0x%x, err=%v", status, err)
	}

	w.sharedMem = baseAddress
	w.argsBuffer = baseAddress + libcallSize  // Arguments buffer starts after libcall struct
	return nil
}

func (w *Worker) placeArgsInSharedMem(task *win32Task) {
	w.sharedMemMtx.Lock()
	defer w.sharedMemMtx.Unlock()

	lc := &libcall{
		fn: task.fn,
		n:  uintptr(len(task.args)),
	}

	if len(task.args) > 0 {
		if len(task.args) > maxArgs {
			panic(fmt.Sprintf("too many arguments: %d (max %d)", len(task.args), maxArgs))
		}
		
		// Copy arguments to the stable buffer
		argsSize := uintptr(len(task.args)) * unsafe.Sizeof(uintptr(0))
		var bytesWritten uintptr
		status, err := NtWriteVirtualMemory(
			0xFFFFFFFFFFFFFFFF, // Current process
			w.argsBuffer,
			uintptr(unsafe.Pointer(&task.args[0])),
			argsSize,
			&bytesWritten,
		)
		
		if err != nil || status != 0 || bytesWritten != argsSize {
			panic(fmt.Sprintf("fatal: NtWriteVirtualMemory failed for args: status=0x%x, err=%v", status, err))
		}
		
		// point to the stable buffer
		lc.args = w.argsBuffer
	} else {
		lc.args = 0
	}

	// write the libcall struct
	var bytesWritten uintptr
	status, err := NtWriteVirtualMemory(
		0xFFFFFFFFFFFFFFFF, // Current process
		w.sharedMem,
		uintptr(unsafe.Pointer(lc)),
		libcallSize,
		&bytesWritten,
	)

	if err != nil || status != 0 || bytesWritten != libcallSize {
		panic(fmt.Sprintf("fatal: NtWriteVirtualMemory failed in worker: status=0x%x, err=%v", status, err))
	}
}

func (w *Worker) retrieveResultFromSharedMem() uintptr {
	w.sharedMemMtx.Lock()
	defer w.sharedMemMtx.Unlock()

	var result uintptr
	var bytesRead uintptr
	
	// read the r1 field from the libcall struct in shared memory.
	// the offset of r1 is 24 bytes.
	status, err := NtReadVirtualMemory(
		0xFFFFFFFFFFFFFFFF, // Current process
		w.sharedMem+24,      // Address of the r1 field
		uintptr(unsafe.Pointer(&result)),
		unsafe.Sizeof(result),
		&bytesRead,
	)

	if err != nil || status != 0 || bytesRead != unsafe.Sizeof(result) {
		panic(fmt.Sprintf("fatal: NtReadVirtualMemory failed in worker: status=0x%x, err=%v", status, err))
	}

	return result
}
