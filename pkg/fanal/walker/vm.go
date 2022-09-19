package walker

import "io/fs"

type VM struct {
	walker
}

func NewVM(skipFiles, skipDirs []string) VM {
	return VM{
		walker: newWalker(skipFiles, skipDirs),
	}
}

// Walk arguments type WalkFunc is
// func(filePath string, info os.FileInfo, opener analyzer.Opener) error
func (w VM) Walk(filesystem fs.FS, root string, fn fs.WalkDirFunc) error {
	fs.WalkDir(filesystem, root, fn)
	return nil
}
