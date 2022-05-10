/* Copyright (c) 2021 SUSE LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package ndb

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unsafe"

	dbi "github.com/knqyf263/go-rpmdb/pkg/db"
	"golang.org/x/xerrors"
)

/* The "New" Database format by RPM is currently not well documented outside
   source code, which is located here:

   https://github.com/rpm-software-management/rpm/blob/rpm-4.17.0-release/lib/backend/ndb/rpmpkg.c

   The format can be summarized this way:

   Packages.db File Format:
   ========================

   32 bytes "NDB Header": Format Magic header, with version number etc. Provides the
   Slot Pages count "SlotNPages".

   Immediately following the NDB Header is an array of "SlotNPages" count Slot Pages.
   Each Slot Page is exactly 4k in size and contains NDB_SlotEntriesPerPage individual Slots.

   Each Slot Entry can be referring to a Package with an identifier or be a free slot entry (Package
   index is zero). If a Slot Entry is non-free, the BlkOffset points to the "Block".

   The "Block" has a "Blob Header", directly followed by the "Blob" (the actual package headers) and
   a Blob "tail" of up to 16 bytes. The "Blob" is checksummed using Adler32 from RFC1950.

   This implementation is currently not validating the blob checksum.
*/

type ndbHeader struct {
	HeaderMagic   uint32
	NDBVersion    uint32
	NDBGeneration uint32
	SlotNPages    uint32
	_             [4]uint32
}

type ndbSlotEntry struct {
	SlotMagic uint32
	PkgIndex  uint32
	BlkOffset uint32
	BlkCount  uint32
}

type ndbBlobHeader struct {
	BlobMagic uint32
	PkgIndex  uint32
	BlobCkSum uint32
	BlobLen   uint32
}

type RpmNDB struct {
	file  *os.File
	slots []ndbSlotEntry
}

const NDB_SlotEntriesPerPage = 4096 / 16 /* 16 == unsafe.Sizeof(NDBSlotEntry) */
const NDB_HeaderMagic = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
const NDB_DBVersion = 0

var ErrorInvalidNDB = xerrors.Errorf("invalid or unsupported NDB format")

func Open(path string) (*RpmNDB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	hdrBuff := ndbHeader{}
	err = binary.Read(file, binary.LittleEndian, &hdrBuff)
	if err != nil {
		return nil, xerrors.Errorf("failed to read metadata: %w", err)
	}

	if hdrBuff.HeaderMagic != NDB_HeaderMagic || hdrBuff.SlotNPages == 0 ||
		hdrBuff.NDBVersion != NDB_DBVersion {
		return nil, ErrorInvalidNDB
	}

	// Sanity check against excessive memory usage
	if hdrBuff.SlotNPages > 2048 {
		return nil, xerrors.Errorf("slot page limit exceeded: %x", hdrBuff.SlotNPages)
	}

	// the first two slots are actually the NDB Header
	slots := make([]ndbSlotEntry, hdrBuff.SlotNPages*NDB_SlotEntriesPerPage-2)
	err = binary.Read(file, binary.LittleEndian, &slots)

	if err != nil {
		return nil, xerrors.Errorf("failed to read NDB slot pages: %w", err)
	}

	return &RpmNDB{
		file:  file,
		slots: slots,
	}, nil
}

func (db *RpmNDB) Read() <-chan dbi.Entry {
	entries := make(chan dbi.Entry)

	go func() {
		defer close(entries)

		const NDB_BlobHeaderSize = int64(unsafe.Sizeof(ndbBlobHeader{}))

		for _, slot := range db.slots {
			const NDB_SlotMagic = 'S' | 'l'<<8 | 'o'<<16 | 't'<<24
			if slot.SlotMagic != NDB_SlotMagic {
				fmt.Println("bad slot magic", slot.SlotMagic)
				entries <- dbi.Entry{
					Err: xerrors.Errorf("bad slot Magic: %x", slot.SlotMagic),
				}
				return
			}
			// Empty slot?
			if slot.PkgIndex == 0 {
				continue
			}
			// Seek to Blob
			_, err := db.file.Seek(int64(slot.BlkOffset)*NDB_BlobHeaderSize, io.SeekStart)
			if err != nil {
				entries <- dbi.Entry{
					Err: err,
				}
				return
			}

			// Read Blob Header
			blobHeaderBuff := ndbBlobHeader{}
			err = binary.Read(db.file, binary.LittleEndian, &blobHeaderBuff)
			if err != nil {
				entries <- dbi.Entry{
					Err: err,
				}
				return
			}
			const NDB_BlobMagic = 'B' | 'l'<<8 | 'b'<<16 | 'S'<<24
			if blobHeaderBuff.BlobMagic != NDB_BlobMagic {
				entries <- dbi.Entry{
					Err: xerrors.Errorf("unexpected NDB blob Magic for pkg %d: %x", slot.PkgIndex, blobHeaderBuff.BlobMagic),
				}
			}
			if blobHeaderBuff.PkgIndex != slot.PkgIndex {
				entries <- dbi.Entry{
					Err: xerrors.Errorf("failed to find NDB blob for pkg %d", slot.PkgIndex),
				}
			}
			// ### check that BlkCnt == (BLOBHEAD_SIZE + bloblen + BLOBTAIL_SIZE + PKGDB_BLK_SIZE - 1) / PKGDB_BLK_SIZE)

			// Read Blob Content
			BlobEntry := make([]byte, blobHeaderBuff.BlobLen)
			_, err = db.file.Read(BlobEntry)
			entries <- dbi.Entry{
				Value: BlobEntry,
				Err:   err,
			}
		}
	}()

	return entries
}
