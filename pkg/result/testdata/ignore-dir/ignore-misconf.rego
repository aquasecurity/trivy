package trivy

import data.lib.trivy

default ignore=false

ignore {
	input.AVDID != "AVD-ID100"
}
