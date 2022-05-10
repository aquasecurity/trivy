package bdb

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/xerrors"
)

// source: https://github.com/berkeleydb/libdb/blob/5b7b02ae052442626af54c176335b67ecc613a30/src/dbinc/db_page.h#L73
type GenericMetadataPage struct {
	LSN           [8]byte  `struct:"[8]byte"`  /* 00-07: LSN. */
	PageNo        uint32   `struct:"uint32"`   /* 08-11: Current page number. */
	Magic         uint32   `struct:"uint32"`   /* 12-15: Magic number. */
	Version       uint32   `struct:"uint32"`   /* 16-19: Version. */
	PageSize      uint32   `struct:"uint32"`   /* 20-23: Pagesize. */
	EncryptionAlg uint8    `struct:"uint8"`    /*    24: Encryption algorithm. */
	PageType      uint8    `struct:"uint8"`    /*    25: Page type. */
	MetaFlags     uint8    `struct:"uint8"`    /* 26: Meta-only flags */
	Unused1       uint8    `struct:"uint8"`    /* 27: Unused. */
	Free          uint32   `struct:"uint32"`   /* 28-31: Free list page number. */
	LastPageNo    uint32   `struct:"uint32"`   /* 32-35: Page number of last page in db. */
	NParts        uint32   `struct:"uint32"`   /* 36-39: Number of partitions. */
	KeyCount      uint32   `struct:"uint32"`   /* 40-43: Cached key count. */
	RecordCount   uint32   `struct:"uint32"`   /* 44-47: Cached record count. */
	Flags         uint32   `struct:"uint32"`   /* 48-51: Flags: unique to each AM. */
	UniqueFileID  [19]byte `struct:"[19]byte"` /* 52-71: Unique file ID. */
}

func ParseGenericMetadataPage(data []byte) (*GenericMetadataPage, error) {
	var metadata GenericMetadataPage

	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &metadata)

	if err != nil {
		return nil, xerrors.Errorf("failed to unpack GenericMetadataPage: %w", err)
	}

	return &metadata, metadata.validate()
}

func (p *GenericMetadataPage) validate() error {
	if p.EncryptionAlg != NoEncryptionAlgorithm {
		return xerrors.Errorf("unexpected encryption algorithm: %+v", p.EncryptionAlg)
	}

	return nil
}
