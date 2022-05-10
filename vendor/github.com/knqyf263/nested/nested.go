package nested

import (
	"errors"
	"strings"
)

var (
	ErrNoSuchKey     = errors.New("no such key")
	ErrUnmatchedType = errors.New("unmatched type")
)

type Nested map[string]interface{}

func (n Nested) GetString(keys []string) (value string, err error) {
	v, err := n.Get(keys)
	if err != nil {
		return "", err
	}
	value, ok := v.(string)
	if !ok {
		return "", ErrUnmatchedType
	}
	return value, nil
}

func (n Nested) GetInt(keys []string) (value int, err error) {
	v, err := n.Get(keys)
	if err != nil {
		return 0, err
	}
	value, ok := v.(int)
	if !ok {
		return 0, ErrUnmatchedType
	}
	return value, nil
}

func (n Nested) GetBool(keys []string) (value bool, err error) {
	v, err := n.Get(keys)
	if err != nil {
		return false, err
	}
	value, ok := v.(bool)
	if !ok {
		return false, ErrUnmatchedType
	}
	return value, nil
}

func (n Nested) GetByString(key, sep string) (value interface{}, err error) {
	key = strings.TrimPrefix(key, sep)
	return n.Get(strings.Split(key, sep))
}

func (n Nested) Get(keys []string) (value interface{}, err error) {
	var ok bool
	m := n
	for i, k := range keys {
		value, ok = m[k]
		if !ok {
			return nil, ErrNoSuchKey
		}
		if i == len(keys)-1 {
			break
		}

		m, ok = value.(map[string]interface{})
		if !ok {
			return nil, ErrNoSuchKey
		}

	}
	return value, nil
}

func (n Nested) SetByString(key, sep string, value interface{}) {
	key = strings.TrimPrefix(key, sep)
	n.Set(strings.Split(key, sep), value)
}

func (n Nested) Set(keys []string, value interface{}) {
	m := n
	for i, k := range keys {
		if i == len(keys)-1 {
			m[k] = value
			return
		}

		v, ok := m[k]
		if ok {
			temp, ok := v.(map[string]interface{})
			if ok {
				m = temp
				continue
			}
		}
		newMap := map[string]interface{}{}
		m[k] = newMap
		m = newMap
	}
	return
}

func (n Nested) DeleteByString(key, sep string) error {
	key = strings.TrimPrefix(key, sep)
	return n.Delete(strings.Split(key, sep))
}

func (n Nested) Delete(keys []string) error {
	m := n
	for i, k := range keys {
		value, ok := m[k]
		if !ok {
			return ErrNoSuchKey
		}

		if i == len(keys)-1 {
			delete(m, k)
			return nil
		}

		m, ok = value.(map[string]interface{})
		if !ok {
			return ErrNoSuchKey
		}
	}
	return nil
}

var SkipKey = errors.New("skip this key")

type WalkFunc func(keys []string, value interface{}) error

func (n Nested) Walk(walkFn WalkFunc) error {
	for k, v := range n {
		err := walk([]string{k}, v, walkFn)
		if err == SkipKey {
			continue
		} else if err != nil {
			return err
		}
	}
	return nil
}

func walk(keys []string, value interface{}, walkFn WalkFunc) error {
	err := walkFn(keys, value)
	if err == SkipKey {
		return nil
	} else if err != nil {
		return err
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}

	for k, v := range m {
		err = walk(append(keys, k), v, walkFn)
		if err != nil {
			return err
		}
	}
	return nil
}
