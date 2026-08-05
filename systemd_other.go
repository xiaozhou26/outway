//go:build !linux

package main

import (
	"errors"

	"github.com/xiaozhou26/outway/internal/config"
)

var errSystemdUnsupported = errors.New("systemd service management is only supported on Linux")

func systemdInstall(config.BootArgs, []string) error { return errSystemdUnsupported }
func systemdEnable(config.BootArgs, []string) error  { return errSystemdUnsupported }
func systemdStart(config.BootArgs, []string) error   { return errSystemdUnsupported }
func systemdRestart(config.BootArgs, []string) error { return errSystemdUnsupported }
func systemdStop() error                             { return errSystemdUnsupported }
func systemdStatus() error                           { return errSystemdUnsupported }
func systemdLogs() error                             { return errSystemdUnsupported }
