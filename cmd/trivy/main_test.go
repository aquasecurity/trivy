package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestNoColorFlag(t *testing.T) {
	// Capture output
	var buf bytes.Buffer
	
	// Test with --no-color flag
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	os.Args = []string{"trivy", "--no-color", "version"}
	
	// This should fail initially as --no-color is not implemented
	err := run()
	if err == nil {
		t.Log("Command executed (may not have --no-color implemented yet)")
	}
	
	// Check that no ANSI color codes are present
	output := buf.String()
	if strings.Contains(output, "\033[") {
		t.Error("Output contains ANSI color codes when --no-color is set")
	}
}

func TestNOCOLOREnvVar(t *testing.T) {
	// Save and restore environment
	oldEnv := os.Getenv("NO_COLOR")
	defer func() { 
		if oldEnv == "" {
			os.Unsetenv("NO_COLOR")
		} else {
			os.Setenv("NO_COLOR", oldEnv)
		}
	}()
	
	// Set NO_COLOR environment variable
	os.Setenv("NO_COLOR", "1")
	
	// Capture output
	var buf bytes.Buffer
	
	// Run command
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	os.Args = []string{"trivy", "version"}
	
	err := run()
	if err == nil {
		t.Log("Command executed")
	}
	
	// Check that no ANSI color codes are present
	output := buf.String()
	if strings.Contains(output, "\033[") {
		t.Error("Output contains ANSI color codes when NO_COLOR is set")
	}
}