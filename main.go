package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/knqyf263/trivy/pkg/gem"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {

	db, err := gem.UpdateDB()
	if err != nil {
		return err
	}

	//fileName := os.Args[1]
	fileName := "Gemfile.lock"
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}

	defer f.Close()

	switch fileName {
	case "Gemfile.lock":
		pkgs, err := gem.ParseLockfile(f)
		if err != nil {
			panic(err)
		}
		for _, pkg := range pkgs {
			for _, advisory := range db[pkg.Name] {
				fmt.Println(pkg.Name)
				fmt.Println(advisory.Cve)
				constraint := strings.Join(advisory.PatchedVersions, " || ")
				constraint = strings.Replace(constraint, ".beta", "-beta", -1)
				c, err := semver.NewConstraint(constraint)
				if err != nil {
					return err
				}
				v, _ := semver.NewVersion(pkg.Version)
				a := c.Check(v)
				fmt.Println(a)

				//constraint := strings.Join(advisory.PatchedVersions, " || ")
				//v1, err := semver.Make("4.2.0-beta4")
				//r, err := semver.ParseRange(constraint)
				//if err != nil {
				//	return err
				//}
				////r, err := semver.ParseRange(">1.0.0 <2.0.0 || >=3.0.0")
				//if r(v1) {
				//	fmt.Println("match")
				//}
			}
		}
	}
	return nil
}
