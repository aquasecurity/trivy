package library

type PackageManager int

const (
	Bundler PackageManager = iota
	Cargo
	Composer
	Npm
	Yarn
	Pipenv
	Poetry
	Unknown
)

func (p PackageManager) String() string {
	switch p {
	case Bundler:
		return "bundler"
	case Cargo:
		return "cargo"
	case Composer:
		return "composer"
	case Npm:
		return "npm"
	case Yarn:
		return "yarn"
	case Pipenv:
		return "pipenv"
	case Poetry:
		return "poetry"
	default:
		return "unknown"
	}
}
