package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/digest"
)

// Performance test for SHA-512 implementation
func benchmarkSHA512Performance() {
	// Test different payload sizes
	sizes := []int{
		100,      // Small file
		1024,     // 1KB
		10240,    // 10KB
		102400,   // 100KB
		1048576,  // 1MB
	}

	fmt.Println("SHA-512 Performance Benchmarks")
	fmt.Println("===============================")

	for _, size := range sizes {
		// Generate random data
		data := make([]byte, size)
		rand.Read(data)
		
		// Benchmark SHA-512
		reader := strings.NewReader(string(data))
		start := time.Now()
		hash, err := digest.CalcSHA512(reader)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("❌ Error calculating SHA-512 for %d bytes: %v\n", size, err)
			continue
		}

		// Calculate throughput
		throughput := float64(size) / duration.Seconds() / 1024 / 1024 // MB/s

		fmt.Printf("✓ %7d bytes: %8.2f ms, %6.2f MB/s - %s\n", 
			size, 
			duration.Seconds()*1000, 
			throughput,
			hash.String()[:20]+"...")
	}
}

// Memory usage test
func testMemoryUsage() {
	fmt.Println("\nMemory Usage Test")
	fmt.Println("================")

	// Test with large data
	largeData := strings.Repeat("A", 10*1024*1024) // 10MB
	reader := strings.NewReader(largeData)

	start := time.Now()
	hash, err := digest.CalcSHA512(reader)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	fmt.Printf("✓ 10MB processed in %v\n", duration)
	fmt.Printf("  Hash: %s\n", hash)
}

// Concurrent processing test
func testConcurrency() {
	fmt.Println("\nConcurrency Test")
	fmt.Println("===============")

	const numGoroutines = 10
	const dataSize = 1024 * 1024 // 1MB each

	results := make(chan time.Duration, numGoroutines)
	
	start := time.Now()
	
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			data := make([]byte, dataSize)
			rand.Read(data)
			reader := strings.NewReader(string(data))
			
			goroutineStart := time.Now()
			_, err := digest.CalcSHA512(reader)
			results <- time.Since(goroutineStart)
			
			if err != nil {
				fmt.Printf("❌ Goroutine %d error: %v\n", id, err)
			}
		}(i)
	}

	var totalDuration time.Duration
	for i := 0; i < numGoroutines; i++ {
		duration := <-results
		totalDuration += duration
	}
	
	wallTime := time.Since(start)
	avgDuration := totalDuration / numGoroutines

	fmt.Printf("✓ %d concurrent 1MB SHA-512 calculations\n", numGoroutines)
	fmt.Printf("  Wall time: %v\n", wallTime)
	fmt.Printf("  Average per goroutine: %v\n", avgDuration)
	fmt.Printf("  Total CPU time: %v\n", totalDuration)
}

// Cross-algorithm comparison
func compareAlgorithms() {
	fmt.Println("\nAlgorithm Comparison")
	fmt.Println("===================")

	data := make([]byte, 1024*1024) // 1MB
	rand.Read(data)
	dataStr := string(data)

	algorithms := []struct {
		name string
		calc func(io.ReadSeeker) (digest.Digest, error)
	}{
		{"SHA-1  ", digest.CalcSHA1},
		{"SHA-256", digest.CalcSHA256},
		{"SHA-512", digest.CalcSHA512},
	}

	for _, alg := range algorithms {
		reader := strings.NewReader(dataStr)
		start := time.Now()
		hash, err := alg.calc(reader)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("❌ %s error: %v\n", alg.name, err)
			continue
		}

		throughput := float64(len(data)) / duration.Seconds() / 1024 / 1024

		fmt.Printf("%s: %8.2f ms, %6.2f MB/s - %s\n", 
			alg.name,
			duration.Seconds()*1000,
			throughput,
			hash.String()[:25]+"...")
	}
}

func main() {
	benchmarkSHA512Performance()
	testMemoryUsage()
	testConcurrency()
	compareAlgorithms()
	
	fmt.Println("\n✅ All performance tests completed successfully!")
}