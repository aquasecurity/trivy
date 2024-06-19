package trivy

import data.lib.trivy

default ignore=false

ignore {
	input.Name == "GPL-3.0"
	input.FilePath == "usr/share/gcc/python/libstdcxx/v6/printers.py"
}

ignore {
	input.RuleID == "generic-unwanted-rule"
	input.Title == "Secret that should not pass filter on rule id"
}
