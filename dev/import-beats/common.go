// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"errors"
	"fmt"
	"strings"
)

// Source code origin:
// github.com/elastic/beats/libbeat/common/mapstr.go

var (
	// errKeyNotFound indicates that the specified key was not found.
	errKeyNotFound = errors.New("key not found")
)

type mapStr map[string]interface{}

// getValue gets a value from the map. If the key does not exist then an error
// is returned.
func (m mapStr) getValue(key string) (interface{}, error) {
	_, _, v, found, err := mapFind(key, m, false)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errKeyNotFound
	}
	return v, nil
}

// put associates the specified value with the specified key. If the map
// previously contained a mapping for the key, the old value is replaced and
// returned. The key can be expressed in dot-notation (e.g. x.y) to put a value
// into a nested map.
//
// If you need insert keys containing dots then you must use bracket notation
// to insert values (e.g. m[key] = value).
func (m mapStr) put(key string, value interface{}) (interface{}, error) {
	// XXX `safemapstr.Put` mimics this implementation, both should be updated to have similar behavior
	k, d, old, _, err := mapFind(key, m, true)
	if err != nil {
		return nil, err
	}

	d[k] = value
	return old, nil
}

// delete deletes the given key from the map.
func (m mapStr) delete(key string) error {
	k, d, _, found, err := mapFind(key, m, false)
	if err != nil {
		return err
	}
	if !found {
		return errKeyNotFound
	}

	delete(d, k)
	return nil
}

// flatten flattens the given MapStr and returns a flat MapStr.
//
// Example:
//
//	"hello": MapStr{"world": "test" }
//
// This is converted to:
//
//	"hello.world": "test"
//
// This can be useful for testing or logging.
func (m mapStr) flatten() mapStr {
	return flatten("", m, mapStr{})
}

// mapFind iterates a mapStr based on a the given dotted key, finding the final
// subMap and subKey to operate on.
// An error is returned if some intermediate is no map or the key doesn't exist.
// If createMissing is set to true, intermediate maps are created.
// The final map and un-dotted key to run further operations on are returned in
// subKey and subMap. The subMap already contains a value for subKey, the
// present flag is set to true and the oldValue return will hold
// the original value.
func mapFind(
	key string,
	data mapStr,
	createMissing bool,
) (subKey string, subMap mapStr, oldValue interface{}, present bool, err error) {
	// XXX `safemapstr.mapFind` mimics this implementation, both should be updated to have similar behavior

	for {
		// Fast path, key is present as is.
		if v, exists := data[key]; exists {
			return key, data, v, true, nil
		}

		idx := strings.IndexRune(key, '.')
		if idx < 0 {
			return key, data, nil, false, nil
		}

		k := key[:idx]
		d, exists := data[k]
		if !exists {
			if createMissing {
				d = mapStr{}
				data[k] = d
			} else {
				return "", nil, nil, false, errKeyNotFound
			}
		}

		v, err := toMapStr(d)
		if err != nil {
			return "", nil, nil, false, err
		}

		// advance to sub-map
		key = key[idx+1:]
		data = v
	}
}

// flatten is a helper for Flatten. See docs for flatten. For convenience the
// out parameter is returned.
func flatten(prefix string, in, out mapStr) mapStr {
	for k, v := range in {
		var fullKey string
		if prefix == "" {
			fullKey = k
		} else {
			fullKey = prefix + "." + k
		}

		if m, ok := tryToMapStr(v); ok {
			flatten(fullKey, m, out)
		} else {
			out[fullKey] = v
		}
	}
	return out
}

// tomapStr performs a type assertion on v and returns a mapStr. v can be either
// a mapStr or a map[string]interface{}. If it's any other type or nil then
// an error is returned.
func toMapStr(v interface{}) (mapStr, error) {
	m, ok := tryToMapStr(v)
	if !ok {
		return nil, fmt.Errorf("expected map but type is %v", v)
	}
	return m, nil
}

func tryToMapStr(v interface{}) (mapStr, bool) {
	switch m := v.(type) {
	case mapStr:
		return m, true
	case map[string]interface{}:
		return m, true
	case map[interface{}]interface{}:
		n := map[string]interface{}{}
		for k, v := range m {
			n[k.(string)] = v
		}
		return n, true
	default:
		return nil, false
	}
}
