// Package server holds the shared server runtime: context, bidirectional IO,
// and the run entry point.
package server

import (
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// Context is re-exported from serverbase for convenience.
type Context = serverbase.Context

// CopyBidirectional is re-exported from serverbase.
var CopyBidirectional = serverbase.CopyBidirectional

// CloseWrite is re-exported from serverbase.
var CloseWrite = serverbase.CloseWrite
