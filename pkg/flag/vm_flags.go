package flag

var (
	vmAWSRegionFlag = Flag{
		Name:       "region",
		ConfigName: "scan.vm.region",
		Value:      "",
		Usage:      "AWS Region to scan",
	}
)

type VMFlagGroups struct {
	AWSRegion *Flag
}

type VMOptions struct {
	AWSRegion string
}

func NewVMFlagGroup() *VMFlagGroups {
	return &VMFlagGroups{
		AWSRegion: &vmAWSRegionFlag,
	}
}

func (f *VMFlagGroups) Name() string {
	return "VM"
}

func (f *VMFlagGroups) Flags() []*Flag {
	return []*Flag{f.AWSRegion}
}

func (f *VMFlagGroups) ToOptions() VMOptions {
	return VMOptions{
		AWSRegion: getString(f.AWSRegion),
	}
}
