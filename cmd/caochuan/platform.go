package main

import (
	"os"

	"github.com/xxff-dot/caochuan/logbuf"
)

func osExit(code int)               { os.Exit(code) }
func newRing() *logbuf.Ring         { return logbuf.New(1000) }
func osExecutable() (string, error) { return os.Executable() }
