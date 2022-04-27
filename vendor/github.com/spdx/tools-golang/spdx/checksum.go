// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package spdx

// ChecksumAlgorithm2_2 represents the algorithm used to generate the file checksum in the Checksum2_2 struct.
type ChecksumAlgorithm string

// The checksum algorithms mentioned in the spdxv2.2.0 https://spdx.github.io/spdx-spec/4-file-information/#44-file-checksum
const (
	SHA224 ChecksumAlgorithm = "SHA224"
	SHA1                     = "SHA1"
	SHA256                   = "SHA256"
	SHA384                   = "SHA384"
	SHA512                   = "SHA512"
	MD2                      = "MD2"
	MD4                      = "MD4"
	MD5                      = "MD5"
	MD6                      = "MD6"
)

//Checksum2_2 struct Provide a unique identifier to match analysis information on each specific file in a package.
// The Algorithm field describes the ChecksumAlgorithm2_2 used and the Value represents the file checksum
type Checksum struct {
	Algorithm ChecksumAlgorithm
	Value     string
}
