package version

type conf struct {
	includePreRelease bool
}

type SpecifierOption interface {
	apply(*conf)
}

type WithPreRelease bool

func (o WithPreRelease) apply(c *conf) {
	c.includePreRelease = bool(o)
}
