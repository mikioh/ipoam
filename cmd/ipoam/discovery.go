// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/mikioh/ipaddr"
	"github.com/mikioh/ipoam"
	"golang.org/x/net/icmp"
)

var rtUsageTmpl = `Usage:
	ipoam {{.Name}} [flags] destination

destination
	A hostname, DNS reg-name or IP address.

`

var (
	cmdRT = &Command{
		Func:      rtMain,
		Usage:     cmdUsage,
		UsageTmpl: rtUsageTmpl,
		CanonName: "rt",
		Aliases:   []string{"pathdisc", "traceroute"},
		Descr:     "Discover an IP-layer path",
	}

	rtPayload []byte
	rtData    = []byte("0123456789abcdefghijklmnopqrstuvwxyz")

	rtIPv4only    bool
	rtIPv6only    bool
	rtNoRevLookup bool
	rtUseICMP     bool
	rtVerbose     bool

	rtMaxHops          int
	rtTC               int
	rtPayloadLen       int
	rtPerHopProbeCount int
	rtPort             int
	rtWait             int

	rtOutboundIf string
	rtSrc        string
)

func init() {
	cmdRT.Flag.BoolVar(&rtIPv4only, "4", false, "Run IPv4 test only")
	cmdRT.Flag.BoolVar(&rtIPv6only, "6", false, "Run IPv6 test only")
	cmdRT.Flag.BoolVar(&rtNoRevLookup, "n", false, "Don't use DNS reverse lookup")
	cmdRT.Flag.BoolVar(&rtUseICMP, "m", false, "Use ICMP for probe packets instead of UDP")
	cmdRT.Flag.BoolVar(&rtVerbose, "v", false, "Show verbose information")

	cmdRT.Flag.IntVar(&rtMaxHops, "hops", 30, "Maximum IPv4 TTL or IPv6 hop-limit")
	cmdRT.Flag.IntVar(&rtTC, "tc", 0, "IPv4 TOS or IPv6 traffic-class on probe packets")
	cmdRT.Flag.IntVar(&rtPayloadLen, "pldlen", 56, "Probe packet payload length")
	cmdRT.Flag.IntVar(&rtPerHopProbeCount, "count", 3, "Per-hop probe count")
	cmdRT.Flag.IntVar(&rtPort, "port", 33434, "Base destination port, range will be [port, port+hops)")
	cmdRT.Flag.IntVar(&rtWait, "wait", 1, "Seconds between transmitting each probe")

	cmdRT.Flag.StringVar(&rtOutboundIf, "if", "", "Outbound interface name")
	cmdRT.Flag.StringVar(&rtSrc, "src", "", "Source IP address")
}

func rtMain(cmd *Command, args []string) {
	if len(args) == 0 {
		cmd.Flag.Usage()
	}

	c, ifi, err := parseDsts(args[0], rtIPv4only, rtIPv6only)
	if err != nil {
		cmd.fatal(err)
	}

	if rtMaxHops > 255 {
		rtMaxHops = 255
	}
	rtPayload = bytes.Repeat(rtData, int(rtPayloadLen)/len(rtData)+1)
	rtPayload = rtPayload[:rtPayloadLen]
	if rtWait <= 0 {
		rtWait = 1
	}
	if rtOutboundIf != "" {
		oif, err := net.InterfaceByName(rtOutboundIf)
		if err == nil {
			ifi = oif
		}
	}
	var src net.IP
	if rtSrc != "" {
		src = net.ParseIP(rtSrc)
		if src.To4() != nil {
			rtIPv4only = true
		}
		if src.To16() != nil && src.To4() == nil {
			rtIPv6only = true
		}
	}

	var ipt *ipoam.Tester
	var dst *ipaddr.Position
	for pos := c.First(); pos != nil; pos = c.Next() {
		if !rtIPv6only && pos.IP.To4() != nil {
			network := "udp4"
			address := "0.0.0.0:0"
			if src != nil {
				address = net.JoinHostPort(src.String(), "0")
			}
			if rtUseICMP {
				network = "ip4:icmp"
				address = "0.0.0.0"
				if src != nil {
					address = src.String()
				}
			}
			ipt, err = ipoam.NewTester(network, address)
			if err != nil {
				cmd.fatal(err)
			}
			defer ipt.Close()
			if rtTC >= 0 {
				ipt.IPv4PacketConn().SetTOS(rtTC)
			}
			dst = pos
			break
		}
		if !rtIPv4only && pos.IP.To16() != nil && pos.IP.To4() == nil {
			network := "udp6"
			address := "[::]:0"
			if src != nil {
				address = net.JoinHostPort(src.String(), "0")
			}
			if rtUseICMP {
				network = "ip6:ipv6-icmp"
				address = "::"
				if src != nil {
					address = src.String()
				}
			}
			ipt, err = ipoam.NewTester(network, address)
			if err != nil {
				cmd.fatal(err)
			}
			defer ipt.Close()
			if rtTC >= 0 {
				ipt.IPv6PacketConn().SetTrafficClass(rtTC)
			}
			dst = pos
			break
		}
	}
	c.Reset(nil)
	if dst == nil {
		cmd.fatal(fmt.Errorf("destination for %s not found", args[0]))
	}

	printRTBanner(args[0], c, dst)

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	cm := ipoam.ControlMessage{ID: os.Getpid() & 0xffff, Seq: 1, Port: rtPort}
	hops := make([]rtHop, 0)
	for i := 1; i <= rtMaxHops; i++ {
		var r ipoam.Report
		hops = hops[:0]

		for j := 0; j < rtPerHopProbeCount; j++ {
			t := time.NewTimer(time.Duration(rtWait) * time.Second)
			defer t.Stop()
			begin := time.Now()
			if !rtIPv6only && dst.IP.To4() != nil {
				ipt.IPv4PacketConn().SetTTL(i)
			}
			if !rtIPv4only && dst.IP.To16() != nil && dst.IP.To4() == nil {
				ipt.IPv6PacketConn().SetHopLimit(i)
			}
			if err := ipt.Probe(rtPayload, &cm, dst.IP, ifi); err != nil {
				fmt.Fprintf(os.Stdout, "error=%q\n", err)
			}

			cm.Seq++
			if cm.Seq > 0xffff {
				cm.Seq = 1
			}
			cm.Port++
			if cm.Port > 0xffff {
				cm.Port = rtPort
			}

			select {
			case <-sig:
				os.Exit(0)
			case <-t.C:
				hops = append(hops, rtHop{rtt: time.Since(begin), r: ipoam.Report{Src: net.IPv6unspecified}})
			case r = <-ipt.Report():
				hops = append(hops, rtHop{rtt: r.Time.Sub(begin), r: r})
			}
		}

		printRTReport(i, hops)
		if hasReached(&r) {
			break
		}
	}
	os.Exit(0)
}

func printRTBanner(dsts string, c *ipaddr.Cursor, pos *ipaddr.Position) {
	bw := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(bw, "Path discovery for %s: %d hops max, %d per-hop probes, %d bytes payload\n", dsts, rtMaxHops, rtPerHopProbeCount, len(rtPayload))
	if len(c.List()) > 1 {
		fmt.Fprintf(bw, "Warning: %s has multiple addresses, using %v\n", dsts, pos.IP)
	}
	bw.Flush()
}

func printRTReport(i int, hops []rtHop) {
	sort.Sort(rtHops(hops))
	bw := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(bw, "% 3d  ", i)
	var prev net.IP
	for _, h := range hops {
		if h.r.Error != nil {
			continue
		}
		if h.r.Src.Equal(prev) {
			fmt.Fprintf(bw, "  %v", h.rtt)
			continue
		}
		if prev != nil {
			fmt.Fprintf(bw, "\n     ")
		}
		if h.r.Src.IsUnspecified() {
			fmt.Fprintf(bw, "*")
		} else {
			if rtNoRevLookup {
				fmt.Fprintf(bw, "%v", h.r.Src)
			} else {
				name := revLookup(h.r.Src.String())
				if name == "" {
					fmt.Fprintf(bw, "%v", h.r.Src)
				} else {
					fmt.Fprintf(bw, "%s (%v)", name, h.r.Src)
				}
			}
			if rtVerbose {
				if h.r.Interface != nil {
					fmt.Fprintf(bw, " if=%s", h.r.Interface.Name)
				}
				switch body := h.r.ICMP.Body.(type) {
				case *icmp.DstUnreach:
					printICMPExtensions(bw, body.Extensions)
				case *icmp.ParamProb:
					printICMPExtensions(bw, body.Extensions)
				case *icmp.TimeExceeded:
					printICMPExtensions(bw, body.Extensions)
				}
			}
		}
		fmt.Fprintf(bw, "  %v", h.rtt)
		prev = h.r.Src
	}
	fmt.Fprintf(bw, "\n")
	bw.Flush()
}

type rtHop struct {
	rtt time.Duration
	r   ipoam.Report
}

type rtHops []rtHop

func (hops rtHops) Len() int { return len(hops) }

func (hops rtHops) Less(i, j int) bool {
	if n := bytes.Compare(hops[i].r.Src, hops[j].r.Src); n < 0 {
		return true
	}
	return false
}

func (hops rtHops) Swap(i, j int) { hops[i], hops[j] = hops[j], hops[i] }

func printICMPExtensions(w io.Writer, exts []icmp.Extension) {
	for _, ext := range exts {
		switch ext := ext.(type) {
		case *icmp.MPLSLabelStack:
			for _, l := range ext.Labels {
				fmt.Fprintf(w, " <label=%d tc=%x s=%t ttl=%d>", l.Label, l.TC, l.S, l.TTL)
			}
		case *icmp.InterfaceInfo:
			fmt.Fprintf(w, " <")
			if ext.Interface != nil {
				fmt.Fprintf(w, "if=%s", ext.Interface.Name)
			}
			if ext.Addr != nil {
				if ext.Interface != nil {
					fmt.Fprintf(w, " ")
				}
				fmt.Fprintf(w, "addr=%v", ext.Addr)
			}
			fmt.Fprintf(w, ">")
		}
	}
}
