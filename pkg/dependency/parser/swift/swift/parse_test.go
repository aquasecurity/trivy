package swift

import (
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
	}{
		// docker run -it --rm swift@sha256:3c62ac97506ecf19ca15e4db57d7930e6a71559b23b19aa57e13d380133a54db
		// mkdir app && cd app
		// swift package init
		// ## add new deps: ##
		// sed -i 's/"1.0.0")/"1.0.0")\n.package(url: "https:\/\/github.com\/ReactiveCocoa\/ReactiveSwift", from: "7.0.0"),\n.package(url: "https:\/\/github.com\/Quick\/Nimble", .exact("9.2.1"))/' Package.swift
		// swift package update
		{
			name:      "happy path v1",
			inputFile: "testdata/happy-v1-Package.resolved",
			want: []types.Library{
				{
					ID:        "github.com/Quick/Nimble@9.2.1",
					Name:      "github.com/Quick/Nimble",
					Version:   "9.2.1",
					Locations: []types.Location{{StartLine: 4, EndLine: 12}},
				},
				{
					ID:        "github.com/ReactiveCocoa/ReactiveSwift@7.1.1",
					Name:      "github.com/ReactiveCocoa/ReactiveSwift",
					Version:   "7.1.1",
					Locations: []types.Location{{StartLine: 13, EndLine: 21}},
				},
			},
		},
		{
			name:      "happy path v2",
			inputFile: "testdata/happy-v2-Package.resolved",
			want: []types.Library{
				{
					ID:        "github.com/Quick/Nimble@9.2.1",
					Name:      "github.com/Quick/Nimble",
					Version:   "9.2.1",
					Locations: []types.Location{{StartLine: 21, EndLine: 29}},
				},
				{
					ID:        "github.com/Quick/Quick@7.2.0",
					Name:      "github.com/Quick/Quick",
					Version:   "7.2.0",
					Locations: []types.Location{{StartLine: 30, EndLine: 38}},
				},
				{
					ID:        "github.com/ReactiveCocoa/ReactiveSwift@7.1.1",
					Name:      "github.com/ReactiveCocoa/ReactiveSwift",
					Version:   "7.1.1",
					Locations: []types.Location{{StartLine: 39, EndLine: 47}},
				},
				{
					ID:        "github.com/element-hq/swift-ogg@0.0.1",
					Name:      "github.com/element-hq/swift-ogg",
					Version:   "0.0.1",
					Locations: []types.Location{{StartLine: 48, EndLine: 56}},
				},
				{
					ID:        "github.com/mattgallagher/CwlCatchException@2.1.2",
					Name:      "github.com/mattgallagher/CwlCatchException",
					Version:   "2.1.2",
					Locations: []types.Location{{StartLine: 3, EndLine: 11}},
				},
				{
					ID:        "github.com/mattgallagher/CwlPreconditionTesting@2.1.2",
					Name:      "github.com/mattgallagher/CwlPreconditionTesting",
					Version:   "2.1.2",
					Locations: []types.Location{{StartLine: 12, EndLine: 20}},
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty-Package.resolved",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			f, err := os.Open(tt.inputFile)
			assert.NoError(t, err)

			libs, _, err := parser.Parse(f)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, libs)
		})
	}
}
