package bdb

const (
	NoEncryptionAlgorithm = 0

	HashMagicNumber = 0x061561

	// the size (in bytes) of an in-page offset
	HashIndexEntrySize = 2
	// all DB pages have the same sized header (in bytes)
	PageHeaderSize = 26

	// all page types supported
	// https://github.com/berkeleydb/libdb/blob/v5.3.28/src/dbinc/db_page.h#L35-L53
	HashUnsortedPageType PageType = 2 // Hash pages created pre 4.6. DEPRECATED
	OverflowPageType     PageType = 7
	HashMetadataPageType PageType = 8
	HashPageType         PageType = 13 // Sorted hash page.

	// https://github.com/berkeleydb/libdb/blob/v5.3.28/src/dbinc/db_page.h#L569-L573
	HashOffIndexPageType PageType = 3 // aka HOFFPAGE

	HashOffPageSize = 12 // (in bytes)
)

type PageType = uint8
