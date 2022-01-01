// Package nodekey
//
// @author: xwc1125
package nodekey

import (
	"fmt"
	"github.com/chain5j/chain5j-protocol/protocol"
)

type option func(f *nodeKey) error

func apply(f *nodeKey, opts ...option) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(f); err != nil {
			return fmt.Errorf("option apply err:%v", err)
		}
	}
	return nil
}

func WithConfig(config protocol.Config) option {
	return func(f *nodeKey) error {
		f.config = config
		return nil
	}
}
