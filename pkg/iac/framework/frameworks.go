package framework

type Framework string

const (
	Default      Framework = "default"
	Experimental Framework = "experimental"
	CIS_AWS_1_2  Framework = "cis-aws-1.2"
	CIS_AWS_1_4  Framework = "cis-aws-1.4"
	ALL          Framework = "all"
)
