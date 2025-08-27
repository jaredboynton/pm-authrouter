package system

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ProcessManager handles process discovery and termination
type ProcessManager struct{}

// NewProcessManager creates a new process manager
func NewProcessManager() *ProcessManager {
	return &ProcessManager{}
}

// FindRunningDaemons finds any currently running instances of this daemon
func (pm *ProcessManager) FindRunningDaemons(targetPort int) ([]int, error) {
	var runningPIDs []int
	currentPID := os.Getpid()

	// Method 1: Find processes with our binary name
	if binaryPIDs := pm.findByBinary(); len(binaryPIDs) > 0 {
		for _, pid := range binaryPIDs {
			if pid != currentPID {
				runningPIDs = append(runningPIDs, pid)
			}
		}
	}

	// Method 2: Find processes listening on target port
	if portPIDs := pm.findByPort(targetPort); len(portPIDs) > 0 {
		for _, pid := range portPIDs {
			if pid != currentPID && !contains(runningPIDs, pid) && pm.isOurProcess(pid) {
				runningPIDs = append(runningPIDs, pid)
			}
		}
	}

	return runningPIDs, nil
}

// findByBinary finds processes by binary name
func (pm *ProcessManager) findByBinary() []int {
	var pids []int

	if runtime.GOOS == "windows" {
		if output := pm.runCommand("wmic", "process", "where", `name="pm-authrouter.exe"`, "get", "ProcessId", "/format:csv"); output != "" {
			pids = pm.parseWindowsWmicPIDs(output, "pm-authrouter.exe")
		}
	} else {
		if output := pm.runCommand("ps", "auxww"); output != "" {
			pids = pm.parseUnixPsPIDs(output, "pm-authrouter")
		}
	}

	return pids
}

// findByPort finds processes listening on specific port
func (pm *ProcessManager) findByPort(port int) []int {
	var pids []int
	targetPort := fmt.Sprintf(":%d", port)

	if runtime.GOOS == "windows" {
		if output := pm.runCommand("netstat", "-ano"); output != "" {
			pids = pm.parseNetstatPIDs(output, targetPort, "LISTENING")
		}
	} else {
		// Try lsof first
		if output := pm.runCommand("lsof", "-i", fmt.Sprintf(":%d", port), "-t"); output != "" {
			pids = pm.parseLsofPIDs(output)
		} else if output := pm.runCommand("netstat", "-tlnp"); output != "" {
			pids = pm.parseNetstatPIDs(output, targetPort, "LISTEN")
		}
	}

	return pids
}

// Helper functions for parsing command output
func (pm *ProcessManager) parseWindowsWmicPIDs(output, processName string) []int {
	var pids []int
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, processName) {
			if parts := strings.Split(line, ","); len(parts) >= 2 {
				if pid, err := strconv.Atoi(strings.TrimSpace(parts[len(parts)-1])); err == nil {
					pids = append(pids, pid)
				}
			}
		}
	}
	return pids
}

func (pm *ProcessManager) parseUnixPsPIDs(output, processName string) []int {
	var pids []int
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, processName) && 
		   !strings.Contains(line, "ps auxww") &&
		   !strings.Contains(line, "timeout") &&
		   !strings.Contains(line, "sudo") &&
		   (strings.Contains(line, "./bin/pm-authrouter") || 
		    strings.Contains(line, "./cmd/pm-authrouter/pm-authrouter") ||
		    strings.Contains(line, "/usr/local/bin/postman/pm-authrouter")) { // Development and production paths
			if parts := strings.Fields(line); len(parts) >= 2 {
				if pid, err := strconv.Atoi(parts[1]); err == nil {
					pids = append(pids, pid)
				}
			}
		}
	}
	return pids
}

func (pm *ProcessManager) parseLsofPIDs(output string) []int {
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line != "" {
			if pid, err := strconv.Atoi(line); err == nil {
				pids = append(pids, pid)
			}
		}
	}
	return pids
}

func (pm *ProcessManager) parseNetstatPIDs(output, targetPort, status string) []int {
	var pids []int
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, targetPort) && strings.Contains(line, status) {
			if parts := strings.Fields(line); len(parts) >= 5 {
				var pidStr string
				if runtime.GOOS == "windows" {
					pidStr = parts[len(parts)-1]
				} else if len(parts) >= 7 && strings.Contains(parts[len(parts)-1], "/") {
					pidStr = strings.Split(parts[len(parts)-1], "/")[0]
				}
				if pidStr != "" {
					if pid, err := strconv.Atoi(pidStr); err == nil {
						pids = append(pids, pid)
					}
				}
			}
		}
	}
	return pids
}

// isOurProcess verifies if a PID belongs to our process
func (pm *ProcessManager) isOurProcess(pid int) bool {
	var output string
	if runtime.GOOS == "windows" {
		output = pm.runCommand("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine", "/format:csv")
	} else {
		output = pm.runCommand("ps", "-p", strconv.Itoa(pid), "-o", "command", "--no-headers")
	}
	return strings.Contains(output, "pm-authrouter")
}

// TerminateExistingDaemons gracefully terminates existing daemon processes
func (pm *ProcessManager) TerminateExistingDaemons(pids []int) error {
	if len(pids) == 0 {
		return nil
	}

	log.Printf("Found %d existing daemon process(es): %v", len(pids), pids)

	for _, pid := range pids {
		if err := pm.terminateProcess(pid); err != nil {
			log.Printf("Warning: Failed to terminate PID %d: %v", pid, err)
		}
	}

	time.Sleep(2 * time.Second)
	log.Println("Existing daemon termination completed")
	return nil
}

// terminateProcess gracefully terminates a single process
func (pm *ProcessManager) terminateProcess(pid int) error {
	log.Printf("Attempting to gracefully terminate daemon PID %d", pid)

	if !pm.processExists(pid) {
		log.Printf("Process %d already terminated", pid)
		return nil
	}

	// Send termination signal
	if err := pm.sendSignal(pid, false); err != nil {
		return fmt.Errorf("failed to send termination signal: %w", err)
	}

	// Wait for graceful shutdown (up to 10 seconds)
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		if !pm.processExists(pid) {
			log.Printf("PID %d terminated gracefully", pid)
			return nil
		}
	}

	// Force kill
	log.Printf("PID %d did not terminate gracefully, forcing termination", pid)
	return pm.sendSignal(pid, true)
}

// processExists checks if a process exists
func (pm *ProcessManager) processExists(pid int) bool {
	if runtime.GOOS == "windows" {
		output := pm.runCommand("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid))
		return !strings.Contains(output, "No tasks are running")
	}
	return pm.runCommandErr("kill", "-0", strconv.Itoa(pid)) == nil
}

// sendSignal sends termination or kill signal to process
func (pm *ProcessManager) sendSignal(pid int, force bool) error {
	if runtime.GOOS == "windows" {
		args := []string{"/PID", strconv.Itoa(pid), "/T"}
		if force {
			args = append(args, "/F")
		}
		return pm.runCommandErr("taskkill", args...)
	}

	signal := "-TERM"
	if force {
		signal = "-KILL"
	}
	return pm.runCommandErr("kill", signal, strconv.Itoa(pid))
}

// runCommand runs a command and returns output, ignoring errors
func (pm *ProcessManager) runCommand(name string, args ...string) string {
	if output, err := exec.Command(name, args...).Output(); err == nil {
		return string(output)
	}
	return ""
}

// runCommandErr runs a command and returns the error
func (pm *ProcessManager) runCommandErr(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// contains checks if slice contains an integer
func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}