package library

type Factory interface {
	NewDriver(filename string) *Driver
}

type DriverFactory struct{}

func (d DriverFactory) NewDriver(filename string) *Driver {
	// TODO: use DI
	var driver Driver
	switch filename {
	case "Gemfile.lock":
		driver = NewBundlerDriver()
	case "Cargo.lock":
		driver = NewCargoDriver()
	case "composer.lock":
		driver = NewComposerDriver()
	case "package-lock.json":
		driver = NewNpmDriver()
	case "yarn.lock":
		driver = NewYarnDriver()
	case "Pipfile.lock":
		driver = NewPipenvDriver()
	case "poetry.lock":
		driver = NewPoetryDriver()
	default:
		return nil
	}
	return &driver
}
