package rpmdb

import (
	"github.com/knqyf263/go-rpmdb/pkg/bdb"
	dbi "github.com/knqyf263/go-rpmdb/pkg/db"
	"github.com/knqyf263/go-rpmdb/pkg/ndb"
	"github.com/knqyf263/go-rpmdb/pkg/sqlite3"
	"golang.org/x/xerrors"
)

type RpmDB struct {
	db dbi.RpmDBInterface
}

func Open(path string) (*RpmDB, error) {
	// SQLite3 Open() returns nil, nil in case of DB format other than SQLite3
	sqldb, err := sqlite3.Open(path)
	if err != nil && !xerrors.Is(err, sqlite3.ErrorInvalidSQLite3) {
		return nil, err
	}
	if sqldb != nil {
		return &RpmDB{db: sqldb}, nil
	}

	// NDB Open() returns nil, nil in case of DB format other than NDB
	ndbh, err := ndb.Open(path)
	if err != nil && !xerrors.Is(err, ndb.ErrorInvalidNDB) {
		return nil, err
	}
	if ndbh != nil {
		return &RpmDB{db: ndbh}, nil
	}

	odb, err := bdb.Open(path)
	if err != nil {
		return nil, err
	}

	return &RpmDB{
		db: odb,
	}, nil

}

func (d *RpmDB) Package(name string) (*PackageInfo, error) {
	pkgs, err := d.ListPackages()
	if err != nil {
		return nil, xerrors.Errorf("unable to list packages: %w", err)
	}

	for _, pkg := range pkgs {
		if pkg.Name == name {
			return pkg, nil
		}
	}
	return nil, xerrors.Errorf("%s is not installed", name)
}

func (d *RpmDB) ListPackages() ([]*PackageInfo, error) {
	var pkgList []*PackageInfo

	for entry := range d.db.Read() {
		if entry.Err != nil {
			return nil, entry.Err
		}

		indexEntries, err := headerImport(entry.Value)
		if err != nil {
			return nil, xerrors.Errorf("error during importing header: %w", err)
		}
		pkg, err := getNEVRA(indexEntries)
		if err != nil {
			return nil, xerrors.Errorf("invalid package info: %w", err)
		}
		pkgList = append(pkgList, pkg)
	}

	return pkgList, nil
}
