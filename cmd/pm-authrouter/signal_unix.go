//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// setupSignalHandling sets up signal handling for Unix systems (macOS, Linux)
func setupSignalHandling(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	
	// Register for Unix-specific signals
	signal.Notify(sigChan, 
		syscall.SIGINT,  // Interrupt from keyboard (Ctrl+C)
		syscall.SIGTERM, // Termination signal (kill command default)
		syscall.SIGHUP,  // Hangup detected on controlling terminal
		syscall.SIGQUIT, // Quit from keyboard (Ctrl+\)
	)
	
	go func() {
		<-sigChan
		cancel()
	}()
}