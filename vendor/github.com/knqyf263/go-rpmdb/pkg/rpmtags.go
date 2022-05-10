package rpmdb

const (
	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L34
	RPMTAG_HEADERIMAGE      = 61
	RPMTAG_HEADERSIGNATURES = 62
	RPMTAG_HEADERIMMUTABLE  = 63
	HEADER_I18NTABLE        = 100
	RPMTAG_HEADERI18NTABLE  = HEADER_I18NTABLE

	// rpmTag_e
	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L34
	RPMTAG_NAME       = 1000
	RPMTAG_VERSION    = 1001
	RPMTAG_RELEASE    = 1002
	RPMTAG_EPOCH      = 1003
	RPMTAG_ARCH       = 1022
	RPMTAG_SOURCERPM  = 1044
	RPMTAG_SIZE       = 1009
	RPMTAG_LICENSE    = 1014
	RPMTAG_VENDOR     = 1011
	RPMTAG_DIRINDEXES = 1116
	RPMTAG_BASENAMES  = 1117
	RPMTAG_DIRNAMES   = 1118

	// rpmTag_enhances
	// https://github.com/rpm-software-management/rpm/blob/rpm-4.16.0-release/lib/rpmtag.h#L375
	RPMTAG_MODULARITYLABEL = 5096

	// rpmTagType_e
	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L431
	RPM_MIN_TYPE          = 0
	RPM_NULL_TYPE         = 0
	RPM_CHAR_TYPE         = 1
	RPM_INT8_TYPE         = 2
	RPM_INT16_TYPE        = 3
	RPM_INT32_TYPE        = 4
	RPM_INT64_TYPE        = 5
	RPM_STRING_TYPE       = 6
	RPM_BIN_TYPE          = 7
	RPM_STRING_ARRAY_TYPE = 8
	RPM_I18NSTRING_TYPE   = 9
	RPM_MAX_TYPE          = 9
)
