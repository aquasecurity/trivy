package misconf

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

func TestScannerOption_Sort(t *testing.T) {
	type fields struct {
		Namespaces  []string
		PolicyPaths []string
		DataPaths   []string
	}
	tests := []struct {
		name   string
		fields fields
		want   ScannerOption
	}{
		{
			name: "happy path",
			fields: fields{
				Namespaces:  []string{"main", "custom", "default"},
				PolicyPaths: []string{"policy"},
				DataPaths:   []string{"data/b", "data/c", "data/a"},
			},
			want: ScannerOption{
				Namespaces:  []string{"custom", "default", "main"},
				PolicyPaths: []string{"policy"},
				DataPaths:   []string{"data/a", "data/b", "data/c"},
			},
		},
		{
			name: "missing some fields",
			fields: fields{
				Namespaces:  []string{"main"},
				PolicyPaths: nil,
				DataPaths:   nil,
			},
			want: ScannerOption{
				Namespaces: []string{"main"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := ScannerOption{
				Namespaces:  tt.fields.Namespaces,
				PolicyPaths: tt.fields.PolicyPaths,
				DataPaths:   tt.fields.DataPaths,
			}
			o.Sort()

			assert.Equal(t, tt.want, o)
		})
	}
}

func TestScanner_Scan(t *testing.T) {
	type fields struct {
		filePatterns []string
		opt          ScannerOption
	}
	type file struct {
		path    string
		content []byte
	}
	tests := []struct {
		name             string
		scannerFunc      func(filePatterns []string, opt ScannerOption) (*Scanner, error)
		fields           fields
		files            []file
		wantFilePath     string
		wantFileType     string
		misconfsExpected int
	}{
		{
			name:        "happy path. Dockerfile",
			scannerFunc: NewDockerfileScanner,
			fields: fields{
				opt: ScannerOption{},
			},
			files: []file{
				{
					path:    "Dockerfile",
					content: []byte(`FROM alpine`),
				},
			},
			wantFilePath:     "Dockerfile",
			wantFileType:     types.Dockerfile,
			misconfsExpected: 1,
		},
		{
			name:        "happy path. Dockerfile with custom file name",
			scannerFunc: NewDockerfileScanner,
			fields: fields{
				filePatterns: []string{"dockerfile:dockerf"},
				opt:          ScannerOption{},
			},
			files: []file{
				{
					path:    "dockerf",
					content: []byte(`FROM alpine`),
				},
			},
			wantFilePath:     "dockerf",
			wantFileType:     types.Dockerfile,
			misconfsExpected: 1,
		},
		{
			name:        "happy path. terraform plan file",
			scannerFunc: NewTerraformPlanScanner,
			fields:      fields{},
			files: []file{
				{
					path:    "main.tfplan.json",
					content: []byte(`{"format_version":"1.1","terraform_version":"1.4.6","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.my-bucket","mode":"managed","type":"aws_s3_bucket","name":"my-bucket","provider_name":"registry.terraform.io/hashicorp/aws","schema_version":0,"values":{"bucket":"evil","force_destroy":false,"tags":null,"timeouts":null},"sensitive_values":{"cors_rule":[],"grant":[],"lifecycle_rule":[],"logging":[],"object_lock_configuration":[],"replication_configuration":[],"server_side_encryption_configuration":[],"tags_all":{},"versioning":[],"website":[]}}]}},"resource_changes":[{"address":"aws_s3_bucket.my-bucket","mode":"managed","type":"aws_s3_bucket","name":"my-bucket","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"bucket":"evil","force_destroy":false,"tags":null,"timeouts":null},"after_unknown":{"acceleration_status":true,"acl":true,"arn":true,"bucket_domain_name":true,"bucket_prefix":true,"bucket_regional_domain_name":true,"cors_rule":true,"grant":true,"hosted_zone_id":true,"id":true,"lifecycle_rule":true,"logging":true,"object_lock_configuration":true,"object_lock_enabled":true,"policy":true,"region":true,"replication_configuration":true,"request_payer":true,"server_side_encryption_configuration":true,"tags_all":true,"versioning":true,"website":true,"website_domain":true,"website_endpoint":true},"before_sensitive":false,"after_sensitive":{"cors_rule":[],"grant":[],"lifecycle_rule":[],"logging":[],"object_lock_configuration":[],"replication_configuration":[],"server_side_encryption_configuration":[],"tags_all":{},"versioning":[],"website":[]}}}],"configuration":{"provider_config":{"aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","expressions":{"profile":{"constant_value":"foo-bar-123123123"},"region":{"constant_value":"us-west-1"}}}},"root_module":{"resources":[{"address":"aws_s3_bucket.my-bucket","mode":"managed","type":"aws_s3_bucket","name":"my-bucket","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"evil"}},"schema_version":0}]}}}`),
				},
			},
			wantFilePath:     "main.tf",
			wantFileType:     types.TerraformPlan,
			misconfsExpected: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a virtual filesystem for testing
			fsys := mapfs.New()
			for _, f := range tt.files {
				err := fsys.WriteVirtualFile(f.path, f.content, 0666)
				require.NoError(t, err)
			}

			s, err := tt.scannerFunc(tt.fields.filePatterns, tt.fields.opt)
			require.NoError(t, err)

			misconfs, err := s.Scan(context.Background(), fsys)
			require.NoError(t, err)
			require.Equal(t, tt.misconfsExpected, len(misconfs), "wrong number of misconfigurations found")
			if tt.misconfsExpected == 1 {
				assert.Equal(t, tt.wantFilePath, misconfs[0].FilePath, "filePaths don't equal")
				assert.Equal(t, tt.wantFileType, misconfs[0].FileType, "fileTypes don't equal")
			}
		})
	}
}

func Test_createPolicyFS(t *testing.T) {
	t.Run("outside pwd", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "subdir/testdir"), 0750))
		f, got, err := createPolicyFS([]string{filepath.Join(tmpDir, "subdir/testdir")})
		require.NoError(t, err)
		assert.Equal(t, []string{"."}, got)

		d, err := f.Open(tmpDir)
		require.NoError(t, err)
		stat, err := d.Stat()
		require.NoError(t, err)
		assert.True(t, stat.IsDir())
	})
}
