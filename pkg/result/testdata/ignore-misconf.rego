package trivy

import data.lib.trivy

default ignore=false

ignore {
	input.ID != "ID-0100"
}
