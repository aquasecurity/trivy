package wheel

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// listing dependencies based on METADATA files
	// docker run --name pipenv --rm -it python:3.7-alpine /bin/sh
	// pip install pipenv
	// find / -wholename "*dist-info/METADATA" | xargs -I {} sh -c 'cat {} | grep -e "^Name:" -e "^Version:" -e "^License:"' | tee METADATAS
	// cat METADATAS | cut -d" " -f2- | sed -e 's/\s\+/#/g' | tr "\n" " " | awk '{for(i=1;i<=NF;i=i+3){printf "\{\""$i"\", \""$(i+1)"\", \""$(i+2)"\"\}\n"}}' |  sed -e 's/#\+/\ /g'

	// finding relevant metadata files for tests
	// mkdir dist-infos
	// find / -wholename "*dist-info/METADATA" | rev | cut -d '/' -f2- | rev | xargs -I % cp -r % dist-infos/
	// find dist-infos/ | grep -v METADATA | xargs rm -R

	// for single METADATA file with known name
	// cat "{{ libname }}.METADATA | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | sed -e 's/\s\+/#/g' | tr "\n" " " | awk '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}' | sed -e 's/#\+/\ /g'
	WheelSimple = []types.Library{
		{"simple", "0.1.0", ""},
	}
	WheelDistlib = []types.Library{
		{"distlib", "0.3.1", "Python license"},
	}
	WheelVirtualenv = []types.Library{
		{"virtualenv", "20.4.2", "MIT"},
	}
)
