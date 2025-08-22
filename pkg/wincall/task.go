package wincall

import (
	"reflect"
	"sync"
	"unsafe"

	"github.com/carved4/go-wincall/pkg/errors"
	"github.com/carved4/go-wincall/pkg/obf"
)

type taskResult struct {
	r1  uintptr
	err error
}

type win32Task struct {
	fn         uintptr
	args       []uintptr
	completion chan taskResult
	argRefs []interface{}
}

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
	nativeWorkerThreadId    uint32
	goWorkerThreadId        uint32
}

var w *Worker
var once sync.Once

func (w *Worker) HNewTaskEvent() uintptr { return w.hNewTaskEvent }
func (w *Worker) HTaskDoneEvent() uintptr { return w.hTaskDoneEvent }
func (w *Worker) SharedMem() uintptr { return w.sharedMem }
func (w *Worker) WaitAddr() uintptr { return w.waitForSingleObjectAddr }
func (w *Worker) WaitNum() uint16 { return w.waitForSingleObjectNum }
func (w *Worker) SetAddr() uintptr { return w.setEventAddr }
func (w *Worker) SetNum() uint16 { return w.setEventNum }
func (w *Worker) NativeWorkerThreadId() uint32 { return w.nativeWorkerThreadId }
func (w *Worker) GoWorkerThreadId() uint32 { return w.goWorkerThreadId }

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
const argsBufferSize = maxArgs * 8

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
		return errors.New(errors.Err1)
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
			panic(errors.New(errors.Err1))
		}

		argsSize := uintptr(len(task.args)) * unsafe.Sizeof(uintptr(0))
		var bytesWritten uintptr
		status, err := NtWriteVirtualMemory(
			0xFFFFFFFFFFFFFFFF,
			w.argsBuffer,
			uintptr(unsafe.Pointer(&task.args[0])),
			argsSize,
			&bytesWritten,
		)

		if err != nil || status != 0 || bytesWritten != argsSize {
			panic(errors.New(errors.Err1))
		}

		lc.args = w.argsBuffer
	} else {
		lc.args = 0
	}

	var bytesWritten uintptr
	status, err := NtWriteVirtualMemory(
		0xFFFFFFFFFFFFFFFF,
		w.sharedMem,
		uintptr(unsafe.Pointer(lc)),
		libcallSize,
		&bytesWritten,
	)

	if err != nil || status != 0 || bytesWritten != libcallSize {
		panic(errors.New(errors.Err1))
	}

	w.encryptLibcallInPlace()
}

func (w *Worker) encryptLibcallInPlace() {
	libcallData := make([]byte, libcallSize)
	var bytesRead uintptr
	status, err := NtReadVirtualMemory(
		0xFFFFFFFFFFFFFFFF,
		w.sharedMem,
		uintptr(unsafe.Pointer(&libcallData[0])),
		libcallSize,
		&bytesRead,
	)
	
	if err != nil || status != 0 || bytesRead != libcallSize {
		return
	}
	
    // Encrypt in place to minimize allocations
    obf.EncodeInPlace(libcallData)
	
	var bytesWritten uintptr
    status, err = NtWriteVirtualMemory(
        0xFFFFFFFFFFFFFFFF,
        w.sharedMem,
        uintptr(unsafe.Pointer(&libcallData[0])),
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
    // Zeroize sensitive buffers
    for i := range libcallData { libcallData[i] = 0 }
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
    // Fast path for common types to avoid reflect allocations
    switch v := arg.(type) {
    case uintptr:
        return v
    case unsafe.Pointer:
        return uintptr(v)
    case *byte, *uint16, *uint32, *uint64, *int8, *int16, *int32, *int64, *int, *uint, *uintptr, *struct{}, *[0]byte:
        return reflect.ValueOf(v).Pointer()
    case int:
        return uintptr(v)
    case int8:
        return uintptr(int64(v))
    case int16:
        return uintptr(int64(v))
    case int32:
        return uintptr(int64(v))
    case int64:
        return uintptr(v)
    case uint:
        return uintptr(v)
    case uint8:
        return uintptr(uint64(v))
    case uint16:
        return uintptr(uint64(v))
    case uint32:
        return uintptr(uint64(v))
    case uint64:
        return uintptr(v)
    case bool:
        if v { return 1 }
        return 0
    }

    // Fallback generic handling
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
    }
    panic(errors.New(errors.Err1))
}
