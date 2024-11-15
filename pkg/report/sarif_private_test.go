package report

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_clearURI(t *testing.T) {
	test := []struct {
		name string
		uri  string
		want string
	}{
		{
			name: "https",
			uri:  "bitbucket.org/hashicorp/terraform-consul-aws",
			want: "bitbucket.org/hashicorp/terraform-consul-aws",
		},
		{
			name: "github",
			uri:  "git@github.com:terraform-aws-modules/terraform-aws-s3-bucket.git?ref=v4.2.0/main.tf",
			want: "github.com/terraform-aws-modules/terraform-aws-s3-bucket/tree/v4.2.0/main.tf",
		},
		{
			name: "git",
			uri:  "git::https://example.com/storage.git?ref=51d462976d84fdea54b47d80dcabbf680badcdb8",
			want: "https://example.com/storage?ref=51d462976d84fdea54b47d80dcabbf680badcdb8",
		},
		{
			name: "git ssh",
			uri:  "git::ssh://username@example.com/storage.git",
			want: "example.com/storage",
		},
		{
			name: "hg",
			uri:  "hg::http://example.com/vpc.hg?ref=v1.2.0",
			want: "http://example.com/vpc?ref=v1.2.0",
		},
		{
			name: "s3",
			uri:  "s3::https://s3-eu-west-1.amazonaws.com/examplecorp-terraform-modules/vpc.zip",
			want: "https://s3-eu-west-1.amazonaws.com/examplecorp-terraform-modules/vpc.zip",
		},
		{
			name: "gcs",
			uri:  "gcs::https://www.googleapis.com/storage/v1/modules/foomodule.zip",
			want: "https://www.googleapis.com/storage/v1/modules/foomodule.zip",
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			got := clearURI(tt.uri)
			require.Equal(t, tt.want, got)
			require.NotNil(t, toUri(got))
		})
	}
}
