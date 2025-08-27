//go:build !windows

package proxy

import "syscall"

// setSOReuseAddr sets SO_REUSEADDR socket option on Unix systems
func (s *Server) setSOReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}