package scanner

import (
	"os"

	"github.com/knqyf263/trivy/pkg/types"

	"github.com/olekukonko/tablewriter"
)

var (
	scanners []Scanner
)

type Scanner interface {
	UpdateDB() error
	ParseLockfile() ([]types.Library, error)
	Scan([]types.Library) ([]types.Vulnerability, error)
}

func Register(s Scanner) {
	scanners = append(scanners, s)
}

func Scan() error {
	for _, s := range scanners {
		err := s.UpdateDB()
		if err != nil {
			return err
		}

		pkg, err := s.ParseLockfile()
		if err != nil {
			return err
		}

		vulns, err := s.Scan(pkg)
		if err != nil {
			return err
		}
		printTable(vulns)
	}
	return nil
}

func printTable(vulns []types.Vulnerability) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Library", "Vulnerability ID", "Title"})

	for _, v := range vulns {
		table.Append([]string{v.LibraryName, v.VulnerabilityID, v.Title})
	}
	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.Render()
}
