//go:build linux

package main

import (
	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/systemd"
)

func systemdInstall(args config.BootArgs, runArgs []string) error {
	return systemd.Default().Install(args, runArgs)
}

func systemdEnable(args config.BootArgs, runArgs []string) error {
	return systemd.Default().Enable(args, runArgs)
}

func systemdStart(args config.BootArgs, runArgs []string) error {
	return systemd.Default().Start(args, runArgs)
}

func systemdRestart(args config.BootArgs, runArgs []string) error {
	return systemd.Default().Restart(args, runArgs)
}

func systemdStop() error   { return systemd.Default().Stop() }
func systemdStatus() error { return systemd.Default().Status() }
func systemdLogs() error   { return systemd.Default().Logs() }
