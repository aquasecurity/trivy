package bdb

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/xerrors"
	"io"
	"os"
)

// source: https://github.com/berkeleydb/libdb/blob/5b7b02ae052442626af54c176335b67ecc613a30/src/dbinc/db_page.h#L259
type HashPage struct {
	LSN            [8]byte `struct:"[8]byte"` /* 00-07: LSN. */
	PageNo         uint32  `struct:"uint32"`  /* 08-11: Current page number. */
	PreviousPageNo uint32  `struct:"uint32"`  /* 12-15: Previous page number. */
	NextPageNo     uint32  `struct:"uint32"`  /* 16-19: Next page number. */
	NumEntries     uint16  `struct:"uint16"`  /* 20-21: Number of items on the page. */
	FreeAreaOffset uint16  `struct:"uint16"`  /* 22-23: High free byte page offset. */
	TreeLevel      uint8   `struct:"uint8"`   /*    24: Btree tree level. */
	PageType       uint8   `struct:"uint8"`   /*    25: Page type. */
}

func ParseHashPage(data []byte) (*HashPage, error) {
	var hashPage HashPage

	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &hashPage)
	if err != nil {
		return nil, xerrors.Errorf("failed to unpack: %w", err)
	}

	return &hashPage, nil
}

func HashPageValueContent(db *os.File, pageData []byte, hashPageIndex uint16, pageSize uint32) ([]byte, error) {
	// the first byte is the page type, so we can peek at it first before parsing further...
	valuePageType := pageData[hashPageIndex]

	// only HOFFPAGE page types have data of interest
	if valuePageType != HashOffIndexPageType {
		return nil, xerrors.Errorf("only HOFFPAGE types supported (%+v)", valuePageType)
	}

	hashOffPageEntryBuff := pageData[hashPageIndex : hashPageIndex+HashOffPageSize]

	entry, err := ParseHashOffPageEntry(hashOffPageEntryBuff)
	if err != nil {
		return nil, err
	}

	var hashValue []byte

	for currentPageNo := entry.PageNo; currentPageNo != 0; {
		pageStart := pageSize * currentPageNo

		_, err := db.Seek(int64(pageStart), io.SeekStart)
		if err != nil {
			return nil, xerrors.Errorf("failed to seek to HashPageValueContent (page=%d): %w", currentPageNo, err)
		}

		currentPageBuff, err := slice(db, int(pageSize))
		if err != nil {
			return nil, xerrors.Errorf("failed to read page=%d: %w", currentPageNo, err)
		}

		currentPage, err := ParseHashPage(currentPageBuff)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse page=%d: %w", currentPageNo, err)
		}
		if currentPage.PageType != OverflowPageType {
			continue
		}

		var hashValueBytes []byte
		if currentPage.NextPageNo == 0 {
			// this is the last page, the whole page contains content
			hashValueBytes = currentPageBuff[PageHeaderSize : PageHeaderSize+currentPage.FreeAreaOffset]
		} else {
			hashValueBytes = currentPageBuff[PageHeaderSize:]
		}

		hashValue = append(hashValue, hashValueBytes...)

		currentPageNo = currentPage.NextPageNo
	}

	return hashValue, nil
}

func HashPageValueIndexes(data []byte, entries uint16) ([]uint16, error) {
	var hashIndexValues = make([]uint16, 0)
	if entries%2 != 0 {
		return nil, xerrors.Errorf("invalid hash index: entries should only come in pairs (%+v)", entries)
	}

	// Every entry is a 2-byte offset that points somewhere in the current database page.
	hashIndexSize := entries * HashIndexEntrySize
	hashIndexData := data[PageHeaderSize : PageHeaderSize+hashIndexSize]

	// data is stored in key-value pairs (https://github.com/berkeleydb/libdb/blob/5b7b02ae052442626af54c176335b67ecc613a30/src/dbinc/db_page.h#L591)
	// skip over keys and only keep values
	const keyValuePairSize = 2 * HashIndexEntrySize
	for idx := range hashIndexData {
		if (idx-HashIndexEntrySize)%keyValuePairSize == 0 {
			value := binary.LittleEndian.Uint16(hashIndexData[idx : idx+2])
			hashIndexValues = append(hashIndexValues, value)
		}
	}

	return hashIndexValues, nil
}

func slice(reader io.Reader, n int) ([]byte, error) {
	newBuff := make([]byte, n)
	numRead, err := reader.Read(newBuff)
	if err != nil {
		return nil, xerrors.Errorf("failed to read page: %w", err)
	}
	if numRead != n {
		return nil, xerrors.Errorf("short page size: %d!=%d", n, numRead)
	}
	return newBuff, nil
}
