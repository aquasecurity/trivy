package digest

import "github.com/mitchellh/hashstructure/v2"

// Source identifies where a digest value was acquired from, so that consumers can tell
// which bytes it covers: values with the same algorithm may cover different byte ranges.
type Source string

func (s Source) String() string {
	return string(s)
}

// Acquisition sources of the digests collected by Trivy.
const (
	// SourceUnknown is used for values that come from outside Trivy's analyzers, such as an
	// SBOM. The covered bytes cannot be determined.
	SourceUnknown Source = "unknown"

	// SourceRPMSigMD5 is the SIGMD5 tag of the RPM database. It covers the main header and
	// the payload, not the whole .rpm file.
	// https://rpm-software-management.github.io/rpm/manual/tags.html#signatures-and-digests
	SourceRPMSigMD5 Source = "rpm-sigmd5"

	// SourceDpkgAvailable is the SHA256 field of /var/lib/dpkg/available.
	// It covers the complete .deb file.
	SourceDpkgAvailable Source = "dpkg-available-sha256"

	// SourceAPKInstalledDB is the C: field of the APK installed database. It covers the
	// compressed control stream, not the whole .apk file.
	// https://wiki.alpinelinux.org/wiki/Apk_spec#Package_Checksum_Field
	SourceAPKInstalledDB Source = "apk-installed-db"

	// SourceJavaArchive is computed by Trivy over a Java archive (JAR/WAR/EAR/PAR,
	// including nested ones). It covers the complete archive.
	SourceJavaArchive Source = "java-archive"

	// SourceFileContent is computed by Trivy over the analyzed file itself, such as METADATA,
	// PKG-INFO, gemspec or package.json. It covers that file, not the distributed package.
	SourceFileContent Source = "file-content"
)

// SourcedDigest is a digest value together with the source it was acquired from.
// The algorithm is part of Digest ("<algorithm>:<value>"), so it is never stored twice.
type SourcedDigest struct {
	Digest Digest `json:",omitempty"`
	Source Source `json:",omitempty"`
}

// Hash identifies a digest by its value alone: the source records where a value came from,
// not what it identifies. hashstructure calls this instead of walking the struct, which
// keeps the hashes identifying SBOM elements independent of whether the source is known.
func (s SourcedDigest) Hash() (uint64, error) {
	return hashstructure.Hash(string(s.Digest), hashstructure.FormatV2, nil)
}

// Algorithm returns the algorithm of the digest, e.g. sha256.
func (s SourcedDigest) Algorithm() Algorithm {
	return s.Digest.Algorithm()
}

// Value returns the hex-encoded digest value without the algorithm prefix.
func (s SourcedDigest) Value() string {
	return s.Digest.Encoded()
}
