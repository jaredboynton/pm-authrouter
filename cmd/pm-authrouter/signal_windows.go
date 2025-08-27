//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// setupSignalHandling sets up signal handling for Windows
func setupSignalHandling(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	
	go func() {
		<-sigChan
		cancel()
	}()
}