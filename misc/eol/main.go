package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// This script displays EOL dates
func main() {
	fmt.Println("Debian")
	debianEOL()

	fmt.Println("\nUbuntu")
	ubuntuEOL()
}

func debianEOL() {
	f, err := os.Open("data/debian.csv")
	if err != nil {
		panic(err)
	}
	defer f.Close() // nolint: errcheck,gosec

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ",")

		if len(fields) < 6 && fields[0] != "" {
			fmt.Printf("\"%s\": time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),\n", fields[0])
		} else if len(fields) == 6 {
			eol, err := time.Parse("2006-1-2", fields[5])
			if err != nil {
				fmt.Printf("debianEOL: error parsing time: %v\n", err)
			}
			fmt.Printf("\"%s\": time.Date(%d, %d, %d, 23, 59, 59, 0, time.UTC),\n", fields[0], eol.Year(), eol.Month(), eol.Day())
		}
	}
}

func ubuntuEOL() {
	f, err := os.Open("data/ubuntu.csv")
	if err != nil {
		panic(err)
	}
	defer f.Close() // nolint: errcheck,gosec

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ",")
		eol, err := time.Parse("2006-1-2", fields[len(fields)-1])
		if err != nil {
			fmt.Printf("ubuntuEOL: error parsing time: %v\n", err)
		}
		fmt.Printf("\"%s\": time.Date(%d, %d, %d, 23, 59, 59, 0, time.UTC),\n", strings.Fields(fields[0])[0], eol.Year(), eol.Month(), eol.Day())
	}
}
