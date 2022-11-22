package storage

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ebs"
	"github.com/aws/aws-sdk-go/service/ebs/ebsiface"
	ebsfile "github.com/masahiro331/go-ebs-file"
	"github.com/stretchr/testify/assert"

	_ "github.com/aquasecurity/trivy/pkg/fanal/vm/vmdk"
)

type mockEBS struct {
	ebsiface.EBSAPI
}

func (m mockEBS) WalkSnapshotBlocks(ctx context.Context, input *ebs.ListSnapshotBlocksInput, table map[int64]string) (*ebs.ListSnapshotBlocksOutput, map[int64]string, error) {

	return &ebs.ListSnapshotBlocksOutput{
		BlockSize:  aws.Int64(512 << 10), // 512 KB
		VolumeSize: aws.Int64(1),
	}, nil, nil
}

func TestOpen(t *testing.T) {
	type args struct {
		target string
		ebs    ebsfile.EBSAPI
		c      context.Context
	}
	tests := []struct {
		name    string
		args    args
		wantS   *Storage
		wantErr string
	}{
		{
			name: "happy path for file",
			args: args{
				target: "testdata/rawdata.img",
			},
			wantS: &Storage{
				Type: "file",
			},
		},
		{
			name: "happy path for ebs",
			args: args{
				target: "ebs:test-snapshot-id",
				ebs:    ebsfile.NewMockEBS("testdata/rawdata.img", 512<<10, 1<<30),
			},
			wantS: &Storage{
				Type: "ebs",
			},
		},
		{
			name: "sad path unsupported vm format",
			args: args{
				target: "testdata/monolithicSparse.vmdk",
			},
			wantErr: "unsupported type error",
		},
		{
			name: "sad path file not found",
			args: args{
				target: "testdata/no-file",
			},
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotS, err := Open(tt.args.target, tt.args.ebs, tt.args.c)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotS.Type, tt.wantS.Type) {
				t.Errorf("Open() gotS = %v, want %v", gotS.Type, tt.wantS.Type)
			}
			assert.NotNil(t, gotS.Reader)
			assert.NotNil(t, gotS.cache)
			if tt.wantS.Type != "ebs" {
				assert.NotNil(t, gotS.file)
			}
		})
	}
}
