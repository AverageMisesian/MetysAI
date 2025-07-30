package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
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
	http.HandleFunc("/radare2", radare2Handler)
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
