//go:build linux

package main

import (
	"os"
	"syscall"
)

// datasync flushes file data (not unrelated metadata) to the disk.
func datasync(f *os.File, fd int) error {
	return syscall.Fdatasync(fd)
}
