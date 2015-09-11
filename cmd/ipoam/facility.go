// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "os"

var facilityUsageTmpl = `Usage:
	ipoam {{.Name}} [flags] int|interfaces [interface name]

`

var (
	cmdFacility = &Command{
		Func:      facilityMain,
		Usage:     cmdUsage,
		UsageTmpl: facilityUsageTmpl,
		CanonName: "sh",
		Aliases:   []string{"show", "list"},
		Descr:     "Show network facility information",
	}

	facilityIPv4only bool
	facilityIPv6only bool
	facilityBrief    bool
)

func init() {
	cmdFacility.Flag.BoolVar(&facilityIPv4only, "4", false, "Show IPv4 information only")
	cmdFacility.Flag.BoolVar(&facilityIPv6only, "6", false, "Show IPv6 information only")
	cmdFacility.Flag.BoolVar(&facilityBrief, "b", false, "Show brief information")
}

func facilityMain(cmd *Command, args []string) {
	if len(args) == 0 {
		cmd.Flag.Usage()
	}

	if args[0] == "int" || args[0] == "interfaces" {
		facilityIfMain(cmd, args[1:])
		os.Exit(0)
	}
	cmd.Flag.Usage()
}
