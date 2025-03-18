package trivy

import rego.v1

allowed_checks := {
    "AVD-AWS-0089"
}

default ignore := false

ignore if not is_check_allowed

is_check_allowed if input.AVDID in allowed_checks