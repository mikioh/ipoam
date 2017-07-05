// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !plan9,!windows

package main_test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

const pkgPath = "github.com/mikioh/ipoam/cmd/ipoam"

func TestMain(t *testing.T) {
	out, err := exec.Command("go", "build", pkgPath).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v, %s\n", err, string(out))
		exec.Command("go", "clean", pkgPath).Run()
		os.Exit(1)
	}

	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		exec.Command("go", "clean", pkgPath).Run()
		os.Exit(1)
	}
	path := wd + "/ipoam"

	if !testing.Short() {
		for _, args := range [][]string{
			{"ipoam", "cv", "-v", "-count=1", "www.google.com"},
			{"ipoam", "cv", "-v", "-count=1", "-4", "www.google.com"},
			{"ipoam", "cv", "-v", "-count=1", "-6", "www.google.com"},
			{"ipoam", "cv", "-v", "-count=1", "ipv4.google.com"},
			{"ipoam", "cv", "-v", "-count=1", "ipv6.google.com"},
			{"ipoam", "cv", "-v", "-count=1", "www.google.com,golang.org"},

			{"ipoam", "cv", "-v", "-count=1", "8.8.8.8"},
			{"ipoam", "cv", "-v", "-count=1", "8.8.8.8,8.8.4.4"},

			{"ipoam", "rt", "-v", "-hops=2", "www.google.com"},
			{"ipoam", "rt", "-v", "-hops=2", "-4", "www.google.com"},
			{"ipoam", "rt", "-v", "-hops=2", "-6", "www.google.com"},
			{"ipoam", "rt", "-v", "-hops=2", "ipv4.google.com"},
			{"ipoam", "rt", "-v", "-hops=2", "ipv6.google.com"},

			{"ipoam", "rt", "-v", "-hops=2", "8.8.8.8"},
			{"ipoam", "rt", "-v", "-hops=2", "8.8.4.4"},

			{"ipoam", "sh", "int"},
			{"ipoam", "sh", "-b", "int"},
		} {
			cmd := exec.Cmd{Path: path, Args: args}
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Fprintf(os.Stdout, "%v, %s\n", err, string(out))
				continue
			}
			if testing.Verbose() {
				fmt.Fprintf(os.Stdout, "%s\n", string(out))
				continue
			}
		}
	}
	exec.Command("go", "clean", pkgPath).Run()
	os.Exit(0)
}
