package trivy

import data.lib.trivy

default ignore=false

ignore {
	input.ID != "AVD-ID-0100"
}
