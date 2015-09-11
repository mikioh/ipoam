// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"text/template"
)

var usageTmpl = `Usage:
	ipoam command [flags] [arguments]

The commands are:{{range .}}
	{{.Name | printf "%-23s"}} {{.Descr}} {{end}}
`

var commands = []*Command{
	cmdCV,
	cmdRT,
	cmdFacility,
}

type Command struct {
	Flag      flag.FlagSet
	Func      func(*Command, []string)
	Usage     func(*Command)
	UsageTmpl string
	CanonName string
	Aliases   []string
	Descr     string
}

func (cmd *Command) fatal(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}

func (cmd *Command) match(name string) bool {
	if name == cmd.CanonName {
		return true
	}
	for _, alias := range cmd.Aliases {
		if name == alias {
			return true
		}
	}
	return false
}

func (cmd *Command) Name() string {
	s := cmd.CanonName
	for _, alias := range cmd.Aliases {
		s += "|" + alias
	}
	return s
}

func main() {
	flag.Usage = func() {
		bw := bufio.NewWriter(os.Stderr)
		t := template.New("ipoam")
		template.Must(t.Parse(usageTmpl))
		if err := t.Execute(bw, commands); err != nil {
			panic(err)
		}
		bw.Flush()
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
	}

	for _, cmd := range commands {
		if !cmd.match(args[0]) {
			continue
		}
		cmd.Flag.Usage = func() { cmd.Usage(cmd) }
		cmd.Flag.Parse(args[1:])
		cmd.Func(cmd, cmd.Flag.Args())
	}
	flag.Usage()
}

func cmdUsage(cmd *Command) {
	bw := bufio.NewWriter(os.Stderr)
	t := template.New(cmd.CanonName)
	template.Must(t.Parse(cmd.UsageTmpl))
	if err := t.Execute(bw, cmd); err != nil {
		panic(err)
	}
	bw.Flush()
	cmd.Flag.PrintDefaults()
	os.Exit(1)
}
