package rpmdb

import (
	"bytes"
	"encoding/binary"
	"io"
	"unsafe"

	"golang.org/x/xerrors"
)

const (
	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L121-L122
	REGION_TAG_COUNT = int32(unsafe.Sizeof(entryInfo{}))
	REGION_TAG_TYPE  = RPM_BIN_TYPE

	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L113
	headerMaxbytes = 256 * 1024 * 1024
)

var (
	// https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L52
	typeSizes = [16]int{
		0,  /*!< RPM_NULL_TYPE */
		1,  /*!< RPM_CHAR_TYPE */
		1,  /*!< RPM_INT8_TYPE */
		2,  /*!< RPM_INT16_TYPE */
		4,  /*!< RPM_INT32_TYPE */
		8,  /*!< RPM_INT64_TYPE */
		-1, /*!< RPM_STRING_TYPE */
		1,  /*!< RPM_BIN_TYPE */
		-1, /*!< RPM_STRING_ARRAY_TYPE */
		-1, /*!< RPM_I18NSTRING_TYPE */
		0,
		0,
		0,
		0,
		0,
		0,
	}
	// https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L27-L47
	typeAlign = [16]int{
		1, /*!< RPM_NULL_TYPE */
		1, /*!< RPM_CHAR_TYPE */
		1, /*!< RPM_INT8_TYPE */
		2, /*!< RPM_INT16_TYPE */
		4, /*!< RPM_INT32_TYPE */
		8, /*!< RPM_INT64_TYPE */
		1, /*!< RPM_STRING_TYPE */
		1, /*!< RPM_BIN_TYPE */
		1, /*!< RPM_STRING_ARRAY_TYPE */
		1, /*!< RPM_I18NSTRING_TYPE */
		0,
		0,
		0,
		0,
		0,
		0,
	}
)

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header_internal.h#L14-L20
type entryInfo struct {
	Tag    int32  /*!< Tag identifier. */
	Type   uint32 /*!< Tag data type. */
	Offset int32  /*!< Offset into data segment (ondisk only). */
	Count  uint32 /*!< Number of tag elements. */
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L88-L94
type indexEntry struct {
	Info   entryInfo
	Length int
	Rdlen  int
	Data   []byte
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header_internal.h#L23
type hdrblob struct {
	peList    []entryInfo
	il        int32
	dl        int32
	pvlen     int32
	dataStart int32
	dataEnd   int32
	regionTag int32
	ril       int32
	rdl       int32
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L2044
func headerImport(data []byte) ([]indexEntry, error) {
	blob, err := hdrblobInit(data)
	if err != nil {
		return nil, xerrors.Errorf("failed to initialize header blob: %w", err)
	}
	indexEntries, err := hdrblobImport(*blob, data)
	if err != nil {
		return nil, xerrors.Errorf("failed to import header blob: %w", err)
	}
	return indexEntries, nil
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L1974
func hdrblobInit(data []byte) (*hdrblob, error) {
	var blob hdrblob
	var err error
	reader := bytes.NewReader(data)

	if err = binary.Read(reader, binary.BigEndian, &blob.il); err != nil {
		return nil, xerrors.Errorf("invalid index length: %w", err)
	}
	if err = binary.Read(reader, binary.BigEndian, &blob.dl); err != nil {
		return nil, xerrors.Errorf("invalid data length: %w", err)
	}
	blob.dataStart = int32(unsafe.Sizeof(blob.il)) + int32(unsafe.Sizeof(blob.dl)) + blob.il*int32(unsafe.Sizeof(entryInfo{}))
	blob.pvlen = int32(unsafe.Sizeof(blob.il)) + int32(unsafe.Sizeof(blob.dl)) + blob.il*int32(unsafe.Sizeof(entryInfo{})) + blob.dl
	blob.dataEnd = blob.dataStart + blob.dl

	if blob.il < 1 {
		return nil, xerrors.New("region no tags error")
	}

	blob.peList = make([]entryInfo, blob.il)
	for i := 0; i < int(blob.il); i++ {
		var pe entryInfo
		err = binary.Read(reader, binary.LittleEndian, &pe)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, xerrors.Errorf("failed to read entry info: %w", err)
		}
		blob.peList[i] = pe
	}
	if blob.pvlen >= headerMaxbytes {
		return nil, xerrors.Errorf("blob size(%d) BAD, 8 + 16 * il(%d) + dl(%d)", blob.pvlen, blob.il, blob.dl)
	}

	if err := hdrblobVerifyRegion(&blob, data); err != nil {
		return nil, xerrors.Errorf("failed to verify region in the header blob: %w", err)
	}
	if err := hdrblobVerifyInfo(&blob, data); err != nil {
		return nil, xerrors.Errorf("failed to verify info: %w", err)
	}

	return &blob, nil
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L880
func hdrblobImport(blob hdrblob, data []byte) ([]indexEntry, error) {
	var indexEntries, dribbleIndexEntries []indexEntry
	var err error
	var rdlen int32

	entry := ei2h(blob.peList[0])
	if entry.Tag >= RPMTAG_HEADERI18NTABLE {
		/* An original v3 header, create a legacy region entry for it */
		indexEntries, rdlen, err = regionSwab(data, blob.peList, 0, blob.dataStart, blob.dataEnd)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse legacy index entries: %w", err)
		}
	} else {
		/* Either a v4 header or an "upgraded" v3 header with a legacy region */
		ril := blob.ril
		if entry.Offset == 0 {
			ril = blob.il
		}

		// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L917
		indexEntries, rdlen, err = regionSwab(data, blob.peList[1:ril], 0, blob.dataStart, blob.dataEnd)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse region entries: %w", err)
		}
		if rdlen < 0 {
			return nil, xerrors.New("invalid region length")
		}

		if blob.ril < int32(len(blob.peList)-1) {
			dribbleIndexEntries, rdlen, err = regionSwab(data, blob.peList[ril:], rdlen, blob.dataStart, blob.dataEnd)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse dribble entries: %w", err)
			}
			if rdlen < 0 {
				return nil, xerrors.New("invalid length of dribble entries")
			}

			uniqTagMap := make(map[int32]indexEntry)

			for _, indexEntry := range append(indexEntries, dribbleIndexEntries...) {
				uniqTagMap[indexEntry.Info.Tag] = indexEntry
			}

			var ies []indexEntry
			for _, indexEntry := range uniqTagMap {
				ies = append(ies, indexEntry)
			}

			indexEntries = ies
		}
		rdlen += REGION_TAG_COUNT
	}

	if rdlen != blob.dl {
		return nil, xerrors.Errorf("the calculated length (%d) is different from the data length (%d)", rdlen, blob.dl)
	}
	return indexEntries, nil
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L298-L303
func hdrblobVerifyInfo(blob *hdrblob, data []byte) error {
	var end int32

	peOffset := 0
	if blob.regionTag != 0 {
		peOffset = 1
	}

	for _, pe := range blob.peList[peOffset:] {
		info := ei2h(pe)

		if end > info.Offset {
			return xerrors.Errorf("invalid offset info: %+v", info)
		}

		if hdrchkTag(info.Tag) {
			return xerrors.Errorf("invalid tag info: %+v", info)
		}

		if hdrchkType(info.Type) {
			return xerrors.Errorf("invalid type info: %+v", info)
		}

		if hdrchkAlign(info.Type, info.Offset) {
			return xerrors.Errorf("invalid align info: %+v", info)
		}

		if hdrchkRange(blob.dl, info.Offset) {
			return xerrors.Errorf("invalid range info: %+v", info)
		}

		length := dataLength(data, info.Type, info.Count, blob.dataStart+info.Offset, blob.dataEnd)
		end := info.Offset + int32(length)
		if hdrchkRange(blob.dl, end) || length <= 0 {
			return xerrors.Errorf("invalid data length info: %+v", info)
		}
	}
	return nil
}

func hdrchkTag(tag int32) bool {
	return tag < HEADER_I18NTABLE
}

func hdrchkType(t uint32) bool {
	return t < RPM_MIN_TYPE || t > RPM_MAX_TYPE
}

func hdrchkAlign(t uint32, offset int32) bool {
	return offset&int32(typeAlign[t]-1) != 0
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L1791
func hdrblobVerifyRegion(blob *hdrblob, data []byte) error {
	var einfo entryInfo
	var regionTag int32

	einfo = ei2h(blob.peList[0])

	if einfo.Tag == RPMTAG_HEADERIMAGE ||
		einfo.Tag == RPMTAG_HEADERSIGNATURES ||
		einfo.Tag == RPMTAG_HEADERIMMUTABLE {

		regionTag = einfo.Tag
	}

	if einfo.Tag != regionTag {
		return nil
	}

	if !(einfo.Type == REGION_TAG_TYPE && einfo.Count == uint32(REGION_TAG_COUNT)) {
		return xerrors.New("invalid region tag")
	}

	if hdrchkRange(blob.dl, einfo.Offset+REGION_TAG_COUNT) {
		return xerrors.New("invalid region offset")
	}

	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L1842
	var trailer entryInfo
	regionEnd := blob.dataStart + einfo.Offset
	if err := binary.Read(bytes.NewReader(data[regionEnd:regionEnd+REGION_TAG_COUNT]), binary.LittleEndian, &trailer); err != nil {
		return xerrors.Errorf("failed to parse trailer: %w", err)
	}
	blob.rdl = regionEnd + REGION_TAG_COUNT - blob.dataStart

	if regionTag == RPMTAG_HEADERSIGNATURES && einfo.Tag == RPMTAG_HEADERIMAGE {
		einfo.Tag = RPMTAG_HEADERSIGNATURES
	}

	if !(einfo.Tag == regionTag && einfo.Type == REGION_TAG_TYPE && einfo.Count == uint32(REGION_TAG_COUNT)) {
		return xerrors.New("invalid region trailer")
	}

	einfo = ei2h(trailer)
	einfo.Offset = -einfo.Offset
	blob.ril = einfo.Offset / int32(unsafe.Sizeof(blob.peList[0]))
	if (einfo.Offset%REGION_TAG_COUNT) != 0 || hdrchkRange(blob.il, blob.ril) || hdrchkRange(blob.dl, blob.rdl) {
		return xerrors.Errorf("invalid region size, region %d", regionTag)
	}

	blob.regionTag = regionTag

	return nil
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L158
func hdrchkRange(dl, offset int32) bool {
	return offset < 0 || offset > dl
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header_internal.h#L42
func ei2h(pe entryInfo) entryInfo {
	return entryInfo{
		Type:   HtonlU(pe.Type),
		Count:  HtonlU(pe.Count),
		Offset: Htonl(pe.Offset),
		Tag:    Htonl(pe.Tag),
	}
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L498
func regionSwab(data []byte, peList []entryInfo, dl, dataStart, dataEnd int32) ([]indexEntry, int32, error) {
	indexEntries := make([]indexEntry, len(peList))
	for i := 0; i < len(peList); i++ {
		pe := peList[i]
		indexEntry := indexEntry{Info: ei2h(pe)}

		start := dataStart + indexEntry.Info.Offset
		if start >= dataEnd {
			return nil, 0, xerrors.New("invalid data offset")
		}

		if i < len(peList)-1 && typeSizes[indexEntry.Info.Type] == -1 {
			indexEntry.Length = int(Htonl(peList[i+1].Offset) - indexEntry.Info.Offset)
		} else {
			indexEntry.Length = dataLength(data, indexEntry.Info.Type, indexEntry.Info.Count, start, dataEnd)
		}
		if indexEntry.Length < 0 {
			return nil, 0, xerrors.New("invalid data length")
		}

		end := int(start) + indexEntry.Length
		indexEntry.Data = data[start:end]
		indexEntries[i] = indexEntry

		dl += int32(indexEntry.Length + alignDiff(indexEntry.Info.Type, uint32(dl)))
	}
	return indexEntries, dl, nil
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L440
func dataLength(data []byte, t, count uint32, start, dataEnd int32) int {
	var length int

	switch t {
	case RPM_STRING_TYPE:
		if count != 1 {
			return -1
		}
		length = strtaglen(data, 1, start, dataEnd)
	case RPM_STRING_ARRAY_TYPE, RPM_I18NSTRING_TYPE:
		length = strtaglen(data, count, start, dataEnd)
	default:
		if typeSizes[t] == -1 {
			return -1
		}
		length = typeSizes[t&0xf] * int(count)
		if length < 0 || dataEnd > 0 && start+int32(length) > dataEnd {
			return -1
		}
	}
	return length
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L353
func alignDiff(t, alignSize uint32) int {
	typeSize := typeSizes[t]
	if typeSize > 1 {
		diff := typeSize - (int(alignSize) % typeSize)
		if diff != typeSize {
			return diff
		}
	}
	return 0
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L408
func strtaglen(data []byte, count uint32, start, dataEnd int32) int {
	var length int
	if start >= dataEnd {
		return -1
	}

	for c := count; c > 0; c-- {
		offset := start + int32(length)
		if offset > int32(len(data)) {
			return -1
		}
		length += bytes.IndexByte(data[offset:dataEnd], byte(0x00)) + 1
	}
	return length
}
