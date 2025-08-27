//go:build windows

package proxy

import "syscall"

// setSOReuseAddr sets SO_REUSEADDR socket option on Windows
func (s *Server) setSOReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}