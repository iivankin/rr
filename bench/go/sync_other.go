//go:build !linux

package main

import "os"

// datasync falls back to File.Sync where fdatasync is missing; on darwin
// that is F_FULLFSYNC.
func datasync(f *os.File, fd int) error {
	return f.Sync()
}
