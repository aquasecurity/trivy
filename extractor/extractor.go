package extractor

type FileMap map[string][]byte

type Extractor interface {
	ImageName() (imageName string)
	ImageID() (imageID string, err error)
	ConfigBlob() (configBlob []byte, err error)
	LayerIDs() (layerIDs []string, err error)
	ExtractLayerFiles(diffID string, filenames []string) (layerDigest string, files FileMap, opqDirs []string, whFiles []string, err error)
}
