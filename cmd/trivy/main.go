package main

import (
	"log"
	"os"

	"github.com/knqyf263/trivy/pkg/gem"
	"github.com/knqyf263/trivy/pkg/types"
	"github.com/olekukonko/tablewriter"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {

	//fileName := os.Args[1]
	fileName := "Gemfile.lock"
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	var vulns []types.Vulnerability
	switch fileName {
	case "Gemfile.lock":
		vulns, err = gem.Scan(f)
		if err != nil {
			return err
		}
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Library", "Vulnerability ID", "Title"})

	for _, v := range vulns {
		table.Append([]string{v.LibraryName, v.VulnerabilityID, v.Title})
	}
	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.Render()

	return nil
}
