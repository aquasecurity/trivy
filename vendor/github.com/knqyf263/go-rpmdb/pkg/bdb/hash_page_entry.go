package bdb

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/xerrors"
)

// source: https://github.com/berkeleydb/libdb/blob/5b7b02ae052442626af54c176335b67ecc613a30/src/dbinc/db_page.h#L655
type HashOffPageEntry struct {
	PageType uint8   `struct:"uint8"`   /*    0: Page type. */
	Unused   [3]byte `struct:"[3]byte"` /* 01-03: Padding, unused. */
	PageNo   uint32  `struct:"uint32"`  /* 04-07: Offpage page number. */
	Length   uint32  `struct:"uint32"`  /* 08-11: Total length of item. */
}

func ParseHashOffPageEntry(data []byte) (*HashOffPageEntry, error) {
	var entry HashOffPageEntry

	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &entry)
	if err != nil {
		return nil, xerrors.Errorf("failed to unpack HashOffPageEntry: %w", err)
	}

	return &entry, nil
}
