package wincall

import (
	"fmt"
	"reflect"
	"sync"
	"unsafe"
)

type taskResult struct {
	r1  uintptr
	err error
}

type win32Task struct {
	fn         uintptr
	args       []uintptr
	completion chan taskResult
	// Keep a slice of the original interface{} args to ensure any pointers
	// within them are not garbage collected until the task is complete.
	argRefs []interface{}
}

// worker manages the persistent native worker thread and the task queue.
type Worker struct {
	sync.Mutex
	tasks                   chan *win32Task
	threadLock              sync.Mutex
	hWorkerThread           uintptr
	hNewTaskEvent           uintptr
	hTaskDoneEvent          uintptr
	sharedMem               uintptr
	argsBuffer              uintptr
	sharedMemMtx            sync.Mutex
	waitForSingleObjectAddr uintptr
	waitForSingleObjectNum  uint16
	setEventAddr            uintptr
	setEventNum             uint16
}

var w *Worker
var once sync.Once

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
const argsBufferSize = maxArgs * 8 // 16 args * 8 bytes each = 128 bytes

func (w *Worker) allocSharedMem() error {
	w.sharedMemMtx.Lock()
	defer w.sharedMemMtx.Unlock()

	if w.sharedMem != 0 {
		return nil
	}

	var baseAddress uintptr
	regionSize := uintptr(libcallSize + argsBufferSize)
	status, err := NtAllocateVirtualMemory(0xFFFFFFFFFFFFFFFF, &baseAddress, 0, &regionSize, 0x3000, 0x04)
	if err != nil || status != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed for worker shared memory: status=0x%x, err=%v", status, err)
	}

	w.sharedMem = baseAddress
	w.argsBuffer = baseAddress + libcallSize
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

		lc.args = w.argsBuffer
	} else {
		lc.args = 0
	}

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

	result := *(*uintptr)(unsafe.Pointer(w.sharedMem + 24))

	return result
}

func processArg(arg interface{}) uintptr {
	if arg == nil {
		return 0
	}
	
	val := reflect.ValueOf(arg)
	
	switch val.Kind() {
	case reflect.Ptr, reflect.UnsafePointer:
		return val.Pointer()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return uintptr(val.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return uintptr(val.Uint())
	case reflect.Bool:
		if val.Bool() {
			return 1
		}
		return 0
	default:
		panic(fmt.Sprintf("unsupported argument type: %T", arg))
	}
}
