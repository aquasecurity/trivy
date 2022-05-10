package fixtures

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	yaml "github.com/goccy/go-yaml"
	bolt "go.etcd.io/bbolt"
)

// Loader is the responsible to loading fixtures.
type Loader struct {
	db            *bolt.DB
	fixturesFiles []string
}

type Fixture struct {
	Bucket string      `yaml:"bucket"`
	Pairs  []Fixture   `yaml:"pairs"`
	Key    string      `yaml:"key"`
	Value  interface{} `yaml:"value"`
}

func New(dbPath string, fixturesFiles []string) (*Loader, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}
	return &Loader{
		db:            db,
		fixturesFiles: fixturesFiles,
	}, nil
}

func (l Loader) Load() error {
	for _, f := range l.fixturesFiles {
		b, err := ioutil.ReadFile(f)
		if err != nil {
			return err
		}

		var fixtures []Fixture
		if err := yaml.Unmarshal(b, &fixtures); err != nil {
			return err
		}
		err = l.db.Update(func(tx *bolt.Tx) error {
			for _, fixture := range fixtures {
				bucket, err := tx.CreateBucketIfNotExists([]byte(fixture.Bucket))
				if err != nil {
					return err
				}
				for _, pair := range fixture.Pairs {
					if err := l.load(bucket, pair); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (l Loader) load(bucket *bolt.Bucket, fixture Fixture) error {
	if fixture.Bucket != "" {
		bucket, err := bucket.CreateBucketIfNotExists([]byte(fixture.Bucket))
		if err != nil {
			return err
		}
		for _, pair := range fixture.Pairs {
			if err := l.load(bucket, pair); err != nil {
				return err
			}
		}
	} else {
		var b []byte
		var err error

		switch fixture.Value.(type) {
		case bool, int, byte, float32, float64, string:
			b = []byte(fmt.Sprint(fixture.Value))
		default:
			b, err = json.Marshal(fixture.Value)
			if err != nil {
				return err
			}
		}
		if err = bucket.Put([]byte(fixture.Key), b); err != nil {
			return err
		}
	}
	return nil
}

func (l Loader) DB()*bolt.DB{
	return l.db
}

func (l Loader) Close() error {
	return l.db.Close()
}
