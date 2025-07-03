package report

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
)

const (
	blockSize = 100
	mod       = 37
	eof       = 65535
	tab       = '\t'
	space     = ' '
	lfeed     = '\n'
	cret      = '\r'
)

// computeFirstMod computes mod^blockSize as an int64.
func computeFirstMod() int64 {
	firstMod := int64(1)
	for i := 0; i < blockSize; i++ {
		firstMod *= mod
	}
	return firstMod
}

// generateFingerprintFromReader returns the fingerprint (hash:suffix) for a given file and 1-based line number.
func generateFingerprintFromReader(r io.Reader, targetLine int) (string, error) {

	// Notes on the fingerprint algorithm:
	// - This fingerprinting algorithm is based on the CodeQL implementation for line tracking.
	// - For each line, it computes a rolling hash over the previous 100 non-whitespace characters (including the current line).
	// - If the same hash appears more than once (e.g., for duplicate lines in the same context), a numeric suffix is appended to disambiguate them.
	// - This approach allows for stable, position-independent identification of lines across file changes, useful for tracking code evolves.

	var window [blockSize]int64
	var lineNumbers [blockSize]int
	var targetHash string
	var targetSuffix int

	for i := range lineNumbers {
		lineNumbers[i] = -1
	}

	hashRaw := int64(0)
	firstMod := computeFirstMod()
	index := 0
	lineNumber := 0
	lineStart := true
	prevCR := false
	hashCounts := make(map[string]int)

	// output the current hash and line number
	outputHash := func() {
		hashValue := strconv.FormatUint(uint64(hashRaw), 16)
		suffix := hashCounts[hashValue] + 1
		hashCounts[hashValue] = suffix
		if lineNumbers[index] == targetLine {
			targetHash = hashValue
			targetSuffix = suffix
		}
		lineNumbers[index] = -1
	}

	// update the current hash value and increment the index in the window
	updateHash := func(current int64) {
		begin := window[index]
		window[index] = current
		hashRaw = mod*hashRaw + current - firstMod*begin
		index = (index + 1) % blockSize
	}

	// process a single character
	processCharacter := func(current int64) {
		// skip tabs, spaces, and line feeds that come directly after a carriage return
		if current == space || current == tab || (prevCR && current == lfeed) {
			prevCR = false
			return
		}
		// replace CR with LF
		if current == cret {
			current = lfeed
			prevCR = true
		} else {
			prevCR = false
		}
		if lineNumbers[index] != -1 {
			outputHash()
		}
		if lineStart {
			lineStart = false
			lineNumber++
			lineNumbers[index] = lineNumber
		}
		if current == lfeed {
			lineStart = true
		}
		updateHash(current)
	}

	reader := bufio.NewReader(r)
	for {
		r, size, err := reader.ReadRune()
		if err != nil {
			break
		}
		processCharacter(int64(r))
		// ff multi-byte, skip remaining bytes
		if size > 1 {
			for i := 1; i < size; i++ {
				_, _ = reader.ReadByte()
			}
		}
	}
	processCharacter(eof)

	// flush the remaining lines
	for i := 0; i < blockSize; i++ {
		if lineNumbers[index] != -1 {
			outputHash()
		}
		updateHash(0)
	}

	if targetHash == "" {
		return "", fmt.Errorf("line %d not found in input", targetLine)
	}
	return targetHash + ":" + strconv.Itoa(targetSuffix), nil
}

// Wrapper function to generate a fingerprint from a file.
func generateCodeQLFingerprint(filename string, targetLine int) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return generateFingerprintFromReader(file, targetLine)
}
