package wheel

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// listing dependencies based on METADATA files
	// docker run --name pipenv --rm -it python:3.7-alpine bash
	// pip install pipenv
	// find / -wholename "*dist-info/METADATA" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee METADATAS
	// cat METADATAS | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}' | sort | uniq

	// finding relevant metadata files for tests
	// mkdir dist-infos
	// find / -wholename "*dist-info/METADATA" | rev | cut -d '/' -f2- | rev | xargs -I % cp -r % dist-infos/
	// find dist-infos/ | grep -v METADATA | xargs rm

	// for single METADATA file with known name
	// cat "{{ libname }}.METADATA" | awk 'NR==2,NR==3' | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}'
	WheelSimple = []types.Library{
		{"simple", "0.1.0"},
	}
	WheelDistlib = []types.Library{
		{"distlib", "0.3.1"},
	}
	WheelVirtualenv = []types.Library{
		{"virtualenv", "20.4.2"},
	}
)
