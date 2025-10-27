package image

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArchiveImage_RepoTags(t *testing.T) {
	tests := []struct {
		name         string
		fileName     string
		wantRepoTags []string
	}{
		{
			name:         "docker archive with tags",
			fileName:     "../test/testdata/alpine-311.tar.gz",
			wantRepoTags: []string{"alpine:3.11"},
		},
		{
			name:         "oci archive without tags",
			fileName:     "../test/testdata/test.oci",
			wantRepoTags: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, err := NewArchiveImage(tt.fileName)
			require.NoError(t, err)

			gotRepoTags := img.RepoTags()
			assert.Equal(t, tt.wantRepoTags, gotRepoTags)
		})
	}
}

func TestArchiveImage_RepoDigests(t *testing.T) {
	tests := []struct {
		name            string
		fileName        string
		wantRepoDigests []string
	}{
		{
			name:            "docker archive",
			fileName:        "../test/testdata/alpine-311.tar.gz",
			wantRepoDigests: nil, // Docker archives don't contain digest information
		},
		{
			name:            "oci archive",
			fileName:        "../test/testdata/test.oci",
			wantRepoDigests: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, err := NewArchiveImage(tt.fileName)
			require.NoError(t, err)

			gotRepoDigests := img.RepoDigests()
			assert.Equal(t, tt.wantRepoDigests, gotRepoDigests)
		})
	}
}
