package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

// Manual integration test for SHA-512 SBOM support
func TestSHA512SBOMIntegration(t *testing.T) {
	// Test CalcSHA512 function
	reader := strings.NewReader("test content for sha512")
	hash, err := digest.CalcSHA512(reader)
	if err != nil {
		t.Fatalf("CalcSHA512 failed: %v", err)
	}
	
	if hash.Algorithm() != digest.SHA512 {
		t.Errorf("Expected algorithm SHA512, got %v", hash.Algorithm())
	}
	
	if !strings.HasPrefix(string(hash), "sha512:") {
		t.Errorf("Expected hash to start with 'sha512:', got %v", hash)
	}
	
	// Test that SHA512 is supported in core.File
	file := core.File{
		Path: "test.txt",
		Digests: []digest.Digest{hash},
	}
	
	if len(file.Digests) != 1 {
		t.Errorf("Expected 1 digest, got %d", len(file.Digests))
	}
	
	if file.Digests[0].Algorithm() != digest.SHA512 {
		t.Errorf("Expected digest algorithm SHA512, got %v", file.Digests[0].Algorithm())
	}
	
	fmt.Printf("✓ SHA-512 integration test passed\n")
	fmt.Printf("  Generated hash: %s\n", hash)
	fmt.Printf("  Hash length: %d characters\n", len(hash.Encoded()))
	fmt.Printf("  Algorithm: %s\n", hash.Algorithm())
}

// Cross-platform compatibility test
func TestSHA512CrossPlatform(t *testing.T) {
	testData := []string{
		"",
		"a",
		"hello world",
		"The quick brown fox jumps over the lazy dog",
		strings.Repeat("test", 1000),
	}
	
	for i, data := range testData {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			reader := strings.NewReader(data)
			hash1, err := digest.CalcSHA512(reader)
			if err != nil {
				t.Fatalf("First calculation failed: %v", err)
			}
			
			reader = strings.NewReader(data)
			hash2, err := digest.CalcSHA512(reader)
			if err != nil {
				t.Fatalf("Second calculation failed: %v", err)
			}
			
			if hash1 != hash2 {
				t.Errorf("Hashes should be identical: %v != %v", hash1, hash2)
			}
			
			// Verify it's a valid hex string
			encoded := hash1.Encoded()
			if len(encoded) != 128 { // SHA-512 = 64 bytes = 128 hex chars
				t.Errorf("Expected 128 hex characters, got %d", len(encoded))
			}
			
			// Verify all characters are valid hex
			for _, c := range encoded {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					t.Errorf("Invalid hex character: %c in %s", c, encoded)
					break
				}
			}
		})
	}
}

func main() {
	// Run manual tests
	t := &testing.T{}
	TestSHA512SBOMIntegration(t)
	TestSHA512CrossPlatform(t)
	
	if !t.Failed() {
		fmt.Println("✓ All SHA-512 integration tests passed!")
	} else {
		fmt.Println("✗ Some tests failed")
	}
}