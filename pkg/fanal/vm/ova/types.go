package ova

type References struct {
	Text  string `xml:",chardata"`
	Files File   `xml:"File"`
}

type File struct {
	Text string `xml:",chardata"`
	Href string `xml:"href,attr"`
	ID   string `xml:"id,attr"`
	Size string `xml:"size,attr"`
}

type DiskSection struct {
	Text  string `xml:",chardata"`
	Info  string `xml:"Info"`
	Disks []Disk `xml:"Disk"`
}

type Disk struct {
	Text                    string `xml:",chardata"`
	Capacity                string `xml:"capacity,attr"`
	CapacityAllocationUnits string `xml:"capacityAllocationUnits,attr"`
	DiskId                  string `xml:"diskId,attr"`
	FileRef                 string `xml:"fileRef,attr"`
	Format                  string `xml:"format,attr"`
}

type NetworkSection struct {
	Text     string    `xml:",chardata"`
	Info     string    `xml:"Info"`
	Networks []Network `xml:"Network"`
}

type Network struct {
	Text        string `xml:",chardata"`
	Name        string `xml:"name,attr"`
	Description string `xml:"Description"`
}

type OperatingSystemSection struct {
	Text        string `xml:",chardata"`
	ID          string `xml:"id,attr"`
	OsType      string `xml:"osType,attr"`
	Info        string `xml:"Info"`
	Description string `xml:"Description"`
}

type System struct {
	Text                    string `xml:",chardata"`
	ElementName             string `xml:"ElementName"`
	InstanceID              string `xml:"InstanceID"`
	VirtualSystemIdentifier string `xml:"VirtualSystemIdentifier"`
	VirtualSystemType       string `xml:"VirtualSystemType"`
}

type Item struct {
	Text                string `xml:",chardata"`
	Required            string `xml:"required,attr"`
	AllocationUnits     string `xml:"AllocationUnits"`
	Description         string `xml:"Description"`
	ElementName         string `xml:"ElementName"`
	InstanceID          string `xml:"InstanceID"`
	ResourceType        string `xml:"ResourceType"`
	VirtualQuantity     string `xml:"VirtualQuantity"`
	Address             string `xml:"Address"`
	AddressOnParent     string `xml:"AddressOnParent"`
	HostResource        string `xml:"HostResource"`
	Parent              string `xml:"Parent"`
	AutomaticAllocation string `xml:"AutomaticAllocation"`
	Connection          string `xml:"Connection"`
	ResourceSubType     string `xml:"ResourceSubType"`
}

type VirtualHardwareSection struct {
	Text   string `xml:",chardata"`
	Info   string `xml:"Info"`
	System System `xml:"System"`
	Items  []Item `xml:"Item"`
}

type VirtualSystem struct {
	Text                    string                   `xml:",chardata"`
	ID                      string                   `xml:"id,attr"`
	Info                    string                   `xml:"Info"`
	Name                    string                   `xml:"Name"`
	OperatingSystemSection  OperatingSystemSection   `xml:"OperatingSystemSection"`
	VirtualHardwareSections []VirtualHardwareSection `xml:"VirtualHardwareSection"`
}

type Envelope struct {
	Text  string `xml:",chardata"`
	Xmlns string `xml:"xmlns,attr"`
	Cim   string `xml:"cim,attr"`
	Ovf   string `xml:"ovf,attr"`
	Rasd  string `xml:"rasd,attr"`
	Vmw   string `xml:"vmw,attr"`
	Vssd  string `xml:"vssd,attr"`
	Xsi   string `xml:"xsi,attr"`

	References     References     `xml:"References"`
	DiskSection    DiskSection    `xml:"DiskSection"`
	NetworkSection NetworkSection `xml:"NetworkSection"`
	VirtualSystem  VirtualSystem  `xml:"VirtualSystem"`
}
