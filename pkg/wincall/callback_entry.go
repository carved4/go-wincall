//go:build windows && amd64

package wincall

import (
    "errors"
    "unsafe"
)

// gCallback holds the libcall block used by the foreign-callable entry.
// External code will call into CallbackEntry, which loads the address
// of this struct into CX and jumps to wincall_asmstdcall.
var gCallback libcall

// Backing storage for up to 16 uintptr args to match the asm limit.
var gArgs [16]uintptr

// SetCallbackN configures the callback target and its arguments.
// Up to 16 arguments are supported; additional args will return an error.
func SetCallbackN(fn uintptr, args ...uintptr) error {
    if len(args) > len(gArgs) {
        return errors.New("too many args: max 16 supported")
    }
    // Copy args into static storage
    for i := 0; i < len(args); i++ {
        gArgs[i] = args[i]
    }
    gCallback.fn = fn
    gCallback.n = uintptr(len(args))
    if len(args) > 0 { gCallback.args = uintptr(unsafe.Pointer(&gArgs[0])) } else { gCallback.args = 0 }
    return nil
}

// Populated by assembly with the address of CallbackEntry.
var CallbackEntryPC uintptr

// CallbackPtr returns the raw code pointer to CallbackEntry.
func CallbackPtr() uintptr { return CallbackEntryPC }
