//go:build linux

package sysstat

import "syscall"

func osSync() { syscall.Sync() }
