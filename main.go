package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

const (
	CREATE_NEW_PROCESS_GROUP = 0x00000200
	CREATE_NO_WINDOW         = 0x08000000
)

type Radare2Request struct {
	FilePath string   `json:"filepath"`
	Params   []string `json:"params"`
}

type Radare2Response struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

func radare2Handler(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req Radare2Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Ensure file exists and get absolute path
	absPath, err := filepath.Abs(req.FilePath)
	if err != nil {
		log.Printf("Error getting absolute path: %v", err)
		http.Error(w, fmt.Sprintf("Invalid file path: %v", err), http.StatusBadRequest)
		return
	}

	// Build command args - use absolute path for the file
	args := append(req.Params, absPath)
	log.Printf("Running radare2 command with args: %v", args)
	cmd := exec.Command("./tools/radare2-5.9.8-w64/bin/radare2.exe", args...)
	// Hide or minimize the command window on Windows
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
		}
	}

	output, err := cmd.CombinedOutput()
	resp := Radare2Response{Output: string(output)}
	if err != nil {
		log.Printf("Error running radare2: %v\nOutput: %s", err, output)
		resp.Error = fmt.Sprintf("radare2 error: %v", err)
	} else {
		log.Printf("radare2 output: %s", output)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func main() {
	// Launch the frontend application
	exePath, exeErr := os.Executable()
	var exeDir string
	if exeErr != nil {
		log.Printf("Error getting executable path: %v", exeErr)
		cwd, wdErr := os.Getwd()
		if wdErr != nil {
			log.Printf("Error getting working directory: %v", wdErr)
		} else {
			exeDir = cwd
		}
	} else {
		exeDir = filepath.Dir(exePath)
	}

	// Determine frontend executable location by checking several candidate paths
	cwd, wdErr := os.Getwd()
	if wdErr != nil {
		log.Printf("Error getting working directory: %v", wdErr)
	}
	var frontendExe string
	candidates := []string{
		filepath.Join(exeDir, "..", "dist", "win-unpacked", "AI-Disassembler.exe"),
		filepath.Join(exeDir, "dist", "win-unpacked", "AI-Disassembler.exe"),
		filepath.Join(exeDir, "app", "dist", "win-unpacked", "AI-Disassembler.exe"),
		filepath.Join(cwd, "dist", "win-unpacked", "AI-Disassembler.exe"),
		filepath.Join(cwd, "app", "dist", "win-unpacked", "AI-Disassembler.exe"),
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			frontendExe = p
			break
		}
	}
	if frontendExe == "" {
		log.Fatalf("Could not find frontend executable; tried: %v", candidates)
	}
	log.Printf("Launching frontend: %s", frontendExe)
	frontendCmd := exec.Command(frontendExe)
	// ensure Electron runs with its own directory so it can find resources
	frontendCmd.Dir = filepath.Dir(frontendExe)
	// Don't hide the window for debugging - we want to see if it launches
	// if runtime.GOOS == "windows" {
	//	frontendCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW}
	// }
	if startErr := frontendCmd.Start(); startErr != nil {
		log.Printf("Error launching frontend: %v", startErr)
	} else {
		log.Printf("Frontend process started with PID: %d", frontendCmd.Process.Pid)
	}
	// Start HTTP server, but allow existing instance on port 8080
	listener, listenErr := net.Listen("tcp", ":8080")
	if listenErr != nil {
		log.Printf("Port 8080 already in use, assuming server is running")
	} else {
		go func() {
			http.HandleFunc("/radare2", radare2Handler)
			log.Println("Server started on :8080")
			if serveErr := http.Serve(listener, nil); serveErr != nil {
				log.Printf("HTTP server error: %v", serveErr)
			}
		}()
	}
	// Wait for frontend to exit
	if waitErr := frontendCmd.Wait(); waitErr != nil {
		log.Printf("Frontend exited with error: %v", waitErr)
	}
}
