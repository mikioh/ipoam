// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/mikioh/ipaddr"
)

func facilityIfMain(cmd *Command, args []string) {
	var ift []net.Interface
	if len(args) > 0 {
		ifi, err := net.InterfaceByName(args[0])
		if err != nil {
			cmd.fatal(err)
		}
		ift = append(ift, *ifi)
	}
	if len(ift) == 0 {
		var err error
		ift, err = net.Interfaces()
		if err != nil {
			cmd.fatal(err)
		}
	}

	status := func(ifi *net.Interface) string {
		if ifi.Flags&net.FlagUp == 0 {
			return "down"
		}
		return "up"
	}
	hwaddr := func(ifi *net.Interface) string {
		if len(ifi.HardwareAddr) == 0 {
			return "<nil>"
		}
		return ifi.HardwareAddr.String()
	}
	routed := func(ifi *net.Interface) string {
		ifat, err := ifi.Addrs()
		if err != nil {
			return ""
		}
		var global, linklocal bool
		for _, ifa := range ifat {
			switch ifa := ifa.(type) {
			case *net.IPNet:
				if ifa.IP.IsLinkLocalUnicast() {
					linklocal = true
				}
				if ifa.IP.IsGlobalUnicast() {
					global = true
				}
			case *net.IPAddr:
				if ifa.IP.IsLinkLocalUnicast() {
					linklocal = true
				}
				if ifa.IP.IsGlobalUnicast() {
					global = true
				}
			}
			if global {
				return "global"
			}
		}
		if linklocal {
			return "link-local"
		}
		return ""
	}

	const briefBanner = "%-16s  %-5s  %-6s  %-10s  %-5s  %s\n"
	bw := bufio.NewWriter(os.Stdout)
	if facilityBrief {
		fmt.Fprintf(bw, briefBanner, "Name", "Index", "Status", "Routed", "MTU", "Hardware address")
		for _, ifi := range ift {
			fmt.Fprintf(bw, briefBanner, ifi.Name, fmt.Sprintf("%d", ifi.Index), status(&ifi), routed(&ifi), fmt.Sprintf("%d", ifi.MTU), hwaddr(&ifi))
		}
	} else {
		for _, ifi := range ift {
			fmt.Fprintf(bw, "%s is %s, flags: <%v>, index: %d\n", ifi.Name, status(&ifi), ifi.Flags, ifi.Index)
			fmt.Fprintf(bw, "\tHardware address is %s\n", hwaddr(&ifi))
			fmt.Fprintf(bw, "\tMTU %d bytes\n", ifi.MTU)
			printUnicastAddrs(bw, &ifi)
			printMulticastAddrs(bw, &ifi)
		}
	}
	bw.Flush()
	os.Exit(0)
}

func printUnicastAddrs(w io.Writer, ifi *net.Interface) {
	ifat, err := ifi.Addrs()
	if err != nil {
		return
	}

	var unis = []struct {
		banner string
		ps     []ipaddr.Prefix
	}{
		{"IPv4 link-local unicast addresses:", nil},
		{"IPv4 unicast addresses:", nil},
		{"IPv6 link-local unicast addresses:", nil},
		{"IPv6 unicast addresses:", nil},
	}

	for _, ifa := range ifat {
		var p ipaddr.Prefix
		switch ifa := ifa.(type) {
		case *net.IPNet:
			p.IP = ifa.IP
			p.Mask = ifa.Mask
		case *net.IPAddr:
			p = *newPrefix(ifa.IP)
		}
		if !facilityIPv6only && p.IP.To4() != nil {
			if p.IP.IsLinkLocalUnicast() {
				unis[0].ps = append(unis[0].ps, p)
			} else {
				unis[1].ps = append(unis[1].ps, p)
			}
		}
		if !facilityIPv4only && p.IP.To16() != nil && p.IP.To4() == nil {
			if p.IP.IsLinkLocalUnicast() {
				unis[2].ps = append(unis[2].ps, p)
			} else {
				unis[3].ps = append(unis[3].ps, p)
			}
		}
	}

	for _, uni := range unis {
		if len(uni.ps) == 0 {
			continue
		}
		c := ipaddr.NewCursor(uni.ps)
		fmt.Fprintf(w, "\t%s\n", uni.banner)
		for _, p := range c.List() {
			fmt.Fprintf(w, "\t\t%v\n", p)
		}
	}
}

func printMulticastAddrs(w io.Writer, ifi *net.Interface) {
	ifat, err := ifi.MulticastAddrs()
	if err != nil {
		return
	}

	var grps = []struct {
		banner string
		ps     []ipaddr.Prefix
	}{
		{"IPv4 link-local joined group addresses:", nil},
		{"IPv4 joined group addresses:", nil},
		{"IPv6 interface-local joined group addresses:", nil},
		{"IPv6 link-local joined group addresses:", nil},
		{"IPv6 joined group addresses:", nil},
	}

	for _, ifa := range ifat {
		var p ipaddr.Prefix
		switch ifa := ifa.(type) {
		case *net.IPNet:
			p.IP = ifa.IP
			p.Mask = ifa.Mask
		case *net.IPAddr:
			p = *newPrefix(ifa.IP)
		}
		if !facilityIPv6only && p.IP.To4() != nil {
			if p.IP.IsLinkLocalMulticast() {
				grps[0].ps = append(grps[0].ps, p)
			} else {
				grps[1].ps = append(grps[1].ps, p)
			}
		}
		if !facilityIPv4only && p.IP.To16() != nil && p.IP.To4() == nil {
			if p.IP.IsInterfaceLocalMulticast() {
				grps[2].ps = append(grps[2].ps, p)
			} else if p.IP.IsLinkLocalMulticast() {
				grps[3].ps = append(grps[3].ps, p)
			} else {
				grps[4].ps = append(grps[4].ps, p)
			}
		}
	}

	for _, grp := range grps {
		if len(grp.ps) == 0 {
			continue
		}
		c := ipaddr.NewCursor(grp.ps)
		fmt.Fprintf(w, "\t%s\n\t\t", grp.banner)
		i := 0
		for _, p := range c.List() {
			fmt.Fprintf(w, "%v", p.IP)
			if i < len(grp.ps)-1 {
				fmt.Fprintf(w, " ")
			}
			i++
		}
		fmt.Fprintf(w, "\n")
	}
}
