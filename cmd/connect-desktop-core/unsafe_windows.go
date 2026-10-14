//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

func uintptrPointer(p *byte) uintptr { return uintptr(unsafe.Pointer(p)) }
func copyBlob(b windows.DataBlob) []byte {
	return append([]byte(nil), unsafe.Slice(b.Data, int(b.Size))...)
}
func unsafeSizeSA() uintptr { return unsafe.Sizeof(windows.SecurityAttributes{}) }
