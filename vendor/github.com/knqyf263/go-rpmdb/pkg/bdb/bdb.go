package bdb

import (
	"io"
	"os"

	dbi "github.com/knqyf263/go-rpmdb/pkg/db"
	"golang.org/x/xerrors"
)

var validPageSizes = map[uint32]struct{}{
	512:   {},
	1024:  {},
	2048:  {},
	4096:  {},
	8192:  {},
	16384: {},
	32768: {},
	65536: {},
}

type BerkeleyDB struct {
	file         *os.File
	HashMetadata *HashMetadataPage
}

func Open(path string) (*BerkeleyDB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// read just a bit in to parse at least the metadata...
	metadataBuff := make([]byte, 512)
	_, err = file.Read(metadataBuff)
	if err != nil {
		return nil, xerrors.Errorf("failed to read metadata: %w", err)
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek db file: %w", err)
	}

	hashMetadata, err := ParseHashMetadataPage(metadataBuff)
	if err != nil {
		return nil, err
	}

	if _, ok := validPageSizes[hashMetadata.PageSize]; !ok {
		return nil, xerrors.Errorf("unexpected page size: %+v", hashMetadata.PageSize)
	}

	return &BerkeleyDB{
		file:         file,
		HashMetadata: hashMetadata,
	}, nil

}

func (db *BerkeleyDB) Read() <-chan dbi.Entry {
	entries := make(chan dbi.Entry)

	go func() {
		defer close(entries)

		for pageNum := uint32(0); pageNum <= db.HashMetadata.LastPageNo; pageNum++ {
			pageData, err := slice(db.file, int(db.HashMetadata.PageSize))
			if err != nil {
				entries <- dbi.Entry{
					Err: err,
				}
				return
			}

			// keep track of the start of the next page for the next iteration...
			endOfPageOffset, err := db.file.Seek(0, io.SeekCurrent)
			if err != nil {
				entries <- dbi.Entry{
					Err: err,
				}
				return
			}

			hashPageHeader, err := ParseHashPage(pageData)
			if err != nil {
				entries <- dbi.Entry{
					Err: err,
				}
				return
			}

			if hashPageHeader.PageType != HashUnsortedPageType && // for RHEL/CentOS 5
				hashPageHeader.PageType != HashPageType {
				// skip over pages that do not have hash values
				continue
			}

			hashPageIndexes, err := HashPageValueIndexes(pageData, hashPageHeader.NumEntries)
			if err != nil {
				entries <- dbi.Entry{
					Err: err,
				}
				return
			}

			for _, hashPageIndex := range hashPageIndexes {
				// the first byte is the page type, so we can peek at it first before parsing further...
				valuePageType := pageData[hashPageIndex]

				// Only Overflow pages contain package data, skip anything else.
				if valuePageType != HashOffIndexPageType {
					continue
				}

				// Traverse the page to concatenate the data that may span multiple pages.
				valueContent, err := HashPageValueContent(
					db.file,
					pageData,
					hashPageIndex,
					db.HashMetadata.PageSize,
				)

				entries <- dbi.Entry{
					Value: valueContent,
					Err:   err,
				}

				if err != nil {
					return
				}
			}

			// go back to the start of the next page for reading...
			_, err = db.file.Seek(endOfPageOffset, io.SeekStart)
			if err != nil {
				entries <- dbi.Entry{
					Err: err,
				}
				return
			}
		}

	}()

	return entries
}
