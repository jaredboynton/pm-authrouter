//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"golang.org/x/sys/windows/svc"
)

func main() {
	// Define command line flags
	var (
		serviceCmd = flag.String("service", "", "Service command: install, remove, start, stop")
		runMode    = flag.String("mode", "", "Run mode: service, daemon (default: auto-detect)")
		_          = flag.String("team", "", "Postman team name")      // Used by config package
		_          = flag.String("saml-url", "", "SAML initialization URL") // Used by config package
	)
	flag.Parse()

	// Handle service commands
	if *serviceCmd != "" {
		if err := handleServiceCommand(*serviceCmd); err != nil {
			log.Fatalf("Service command failed: %v", err)
		}
		return
	}

	// Determine if we're running as a service
	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Fatalf("Failed to determine if we are running in an interactive session: %v", err)
	}

	// Override detection with explicit mode if provided
	if *runMode == "service" {
		isIntSess = false
	} else if *runMode == "daemon" {
		isIntSess = true
	}

	if !isIntSess {
		// Running as a Windows service
		runService(serviceName, false)
		return
	}

	// Running interactively as a regular daemon
	runInteractiveDaemon()
}

func handleServiceCommand(cmd string) error {
	switch strings.ToLower(cmd) {
	case "install":
		return installService()
	case "remove", "uninstall":
		return removeService()
	case "start":
		return startService()
	case "stop":
		return stopService()
	default:
		return fmt.Errorf("unknown service command: %s", cmd)
	}
}

func runInteractiveDaemon() {
	// This runs the same daemon code but not as a service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	setupSignalHandling(cancel)

	// Run the daemon
	if err := runDaemon(ctx, nil); err != nil {
		log.Fatalf("Daemon failed: %v", err)
	}

	log.Println("AuthRouter stopped")
}