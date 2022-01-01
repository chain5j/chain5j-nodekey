// Package nodekey
//
// @author: xwc1125
package nodekey

import (
	"github.com/chain5j/logger"
	"sync/atomic"
)

var logIns atomic.Value

func log() logger.Logger {
	if l := logIns.Load(); l != nil {
		return l.(logger.Logger)
	}
	l := logger.New("nodeKey")
	logIns.Store(l)
	return l
}
