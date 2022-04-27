package bdb

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/xerrors"
)

// source: https://github.com/berkeleydb/libdb/blob/5b7b02ae052442626af54c176335b67ecc613a30/src/dbinc/db_page.h#L130
type HashMetadataPage struct {
	GenericMetadataPage
	MaxBucket   uint32 `struct:"uint32"` /* 72-75: ID of Maximum bucket in use */
	HighMask    uint32 `struct:"uint32"` /* 76-79: Modulo mask into table */
	LowMask     uint32 `struct:"uint32"` /* 80-83: Modulo mask into table lower half */
	FillFactor  uint32 `struct:"uint32"` /* 84-87: Fill factor */
	NumKeys     uint32 `struct:"uint32"` /* 88-91: Number of keys in hash table */
	CharKeyHash uint32 `struct:"uint32"` /* 92-95: Value of hash(CHARKEY) */
	// don't care about the rest...
}

func ParseHashMetadataPage(data []byte) (*HashMetadataPage, error) {
	var metadata HashMetadataPage

	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &metadata)
	if err != nil {
		return nil, xerrors.Errorf("failed to unpack HashMetadataPage: %w", err)
	}

	return &metadata, metadata.validate()
}

func (p *HashMetadataPage) validate() error {
	err := p.GenericMetadataPage.validate()
	if err != nil {
		return err
	}

	if p.Magic != HashMagicNumber {
		return xerrors.Errorf("unexpected DB magic number: %+v", p.Magic)
	}

	if p.PageType != HashMetadataPageType {
		return xerrors.Errorf("unexpected page type: %+v", p.PageType)
	}

	return nil
}
