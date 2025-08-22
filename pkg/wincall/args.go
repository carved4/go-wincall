package wincall

import (
    "reflect"
    "unsafe"

    "github.com/carved4/go-wincall/pkg/errors"
)

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

