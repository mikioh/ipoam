// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mikioh/ipaddr"
	"github.com/mikioh/ipoam"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var cvUsageTmpl = `Usage:
	ipoam {{.Name}} [flags] destination

destination
	A hostname, DNS reg-name, IP address, IP address prefix, or
	comma-separated list of IP addresses and/or IP address prefixes.
	A combination of unicast and multicast addresses is prohibited.

`

var (
	cmdCV = &Command{
		Func:      cvMain,
		Usage:     cmdUsage,
		UsageTmpl: cvUsageTmpl,
		CanonName: "cv",
		Aliases:   []string{"ping"},
		Descr:     "Verify IP-layer connectivity",
	}

	cvPayload []byte
	cvData    = []byte("0123456789abcdefghijklmnopqrstuvwxyz")

	cvIPv4only    bool
	cvIPv6only    bool
	cvNoRevLookup bool
	cvQuiet       bool
	cvXmitOnly    bool
	cvVerbose     bool

	cvCount         int
	cvHops          int
	cvMulticastHops int
	cvTC            int
	cvPayloadLen    int
	cvWait          int // allow to run "hidden flooding mode" when cvWait is a negative integer

	cvOutboundIf string
	cvSrc        string
)

func init() {
	cmdCV.Flag.BoolVar(&cvIPv4only, "4", false, "Run IPv4 test only")
	cmdCV.Flag.BoolVar(&cvIPv6only, "6", false, "Run IPv6 test only")
	cmdCV.Flag.BoolVar(&cvNoRevLookup, "n", false, "Don't use DNS reverse lookup")
	cmdCV.Flag.BoolVar(&cvQuiet, "q", false, "Quiet output except summary")
	cmdCV.Flag.BoolVar(&cvXmitOnly, "x", false, "Run transmission only")
	cmdCV.Flag.BoolVar(&cvVerbose, "v", false, "Show verbose information")

	cmdCV.Flag.IntVar(&cvCount, "count", 0, "Iteration count, less than or equal to zero will run until interrupted")
	cmdCV.Flag.IntVar(&cvHops, "hops", 64, "IPv4 TTL or IPv6 hop-limit on outgoing unicast packets")
	cmdCV.Flag.IntVar(&cvMulticastHops, "mchops", 5, "IPv4 TTL or IPv6 hop-limit on outgoing multicast packets")
	cmdCV.Flag.IntVar(&cvTC, "tc", 0, "IPv4 TOS or IPv6 traffic-class on outgoing packets")
	cmdCV.Flag.IntVar(&cvPayloadLen, "pldlen", 56, "ICMP echo payload length")
	cmdCV.Flag.IntVar(&cvWait, "wait", 1, "Seconds between transmitting each echo")

	cmdCV.Flag.StringVar(&cvOutboundIf, "if", "", "Outbound interface name")
	cmdCV.Flag.StringVar(&cvSrc, "src", "", "Source IP address")
}

func cvMain(cmd *Command, args []string) {
	if len(args) == 0 {
		cmd.Flag.Usage()
	}

	bw := bufio.NewWriter(os.Stdout)

	c, ifi, err := parseDsts(args[0], cvIPv4only, cvIPv6only)
	if err != nil {
		cmd.fatal(err)
	}

	cvPayload = bytes.Repeat(cvData, int(cvPayloadLen)/len(cvData)+1)
	cvPayload = cvPayload[:cvPayloadLen]
	if cvWait == 0 {
		cvWait = 1
	}
	if cvOutboundIf != "" {
		oif, err := net.InterfaceByName(cvOutboundIf)
		if err == nil {
			ifi = oif
		}
	}
	var src net.IP
	if cvSrc != "" {
		src = net.ParseIP(cvSrc)
		if src.To4() != nil {
			cvIPv4only = true
		}
		if src.To16() != nil && src.To4() == nil {
			cvIPv6only = true
		}
	}

	var ipts = [2]struct {
		t *ipoam.Tester
		r <-chan ipoam.Report
	}{}
	for _, p := range c.List() {
		if !cvIPv6only && p.IP.To4() != nil && ipts[0].t == nil {
			address := "0.0.0.0"
			if src != nil {
				address = src.String()
			}
			ipts[0].t, err = ipoam.NewTester("ip4:icmp", address)
			if err != nil {
				cmd.fatal(err)
			}
			defer ipts[0].t.Close()
			ipts[0].r = ipts[0].t.Report()
			if cvXmitOnly {
				ipts[0].t.StopReport()
			}
			if p := ipts[0].t.IPv4PacketConn(); p != nil {
				if cvHops >= 0 {
					p.SetTTL(cvHops)
				}
				if cvMulticastHops >= 0 {
					p.SetMulticastTTL(cvMulticastHops)
				}
				if cvTC >= 0 {
					p.SetTOS(cvTC)
				}
			}
		}
		if !cvIPv4only && p.IP.To16() != nil && p.IP.To4() == nil && ipts[1].t == nil {
			address := "::"
			if src != nil {
				address = src.String()
			}
			ipts[1].t, err = ipoam.NewTester("ip6:ipv6-icmp", address)
			if err != nil {
				cmd.fatal(err)
			}
			defer ipts[1].t.Close()
			ipts[1].r = ipts[1].t.Report()
			if cvXmitOnly {
				ipts[1].t.StopReport()
			}
			if p := ipts[1].t.IPv6PacketConn(); p != nil {
				if cvHops >= 0 {
					p.SetHopLimit(cvHops)
				}
				if cvMulticastHops >= 0 {
					p.SetMulticastHopLimit(cvHops)
				}
				if cvTC >= 0 {
					p.SetTrafficClass(cvTC)
				}
			}
		}
		if ipts[0].t != nil && ipts[1].t != nil {
			break
		}
	}

	printCVBanner(bw, args[0], c)

	stats := make(cvStats)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	var onlink ipoam.Report
	cm := ipoam.ControlMessage{ID: os.Getpid() & 0xffff}
	for i := 1; ; i++ {
		t := time.NewTimer(time.Duration(cvWait) * time.Second)
		begin := time.Now()
		cm.Seq = i
		for pos := c.First(); pos != nil; pos = c.Next() {
			if !cvIPv6only && pos.IP.To4() != nil {
				onlink.Error = ipts[0].t.Probe(cvPayload, &cm, pos.IP, ifi)
				stats.get(pos.IP.String()).onDeparture(&onlink)
				if onlink.Error != nil {
					printCVReport(bw, 0, &onlink)
					continue
				}
			}
			if !cvIPv4only && pos.IP.To16() != nil && pos.IP.To4() == nil {
				onlink.Error = ipts[1].t.Probe(cvPayload, &cm, pos.IP, ifi)
				stats.get(pos.IP.String()).onDeparture(&onlink)
				if onlink.Error != nil {
					printCVReport(bw, 0, &onlink)
					continue
				}
			}
		}
		c.Reset(nil)

	loop:
		for {
			select {
			case <-sig:
				if cvVerbose {
					printCVSummary(bw, args[0], stats)
				}
				os.Exit(0)
			case <-t.C:
				break loop
			case r := <-ipts[0].r:
				rtt := time.Since(begin)
				printCVReport(bw, rtt, &r)
				stats.get(r.Src.String()).onArrival(rtt, &r)
			case r := <-ipts[1].r:
				rtt := time.Since(begin)
				printCVReport(bw, rtt, &r)
				stats.get(r.Src.String()).onArrival(rtt, &r)
			}
		}
		t.Stop()

		if cvCount > 0 && i == cvCount {
			if cvVerbose {
				printCVSummary(bw, args[0], stats)
			}
			os.Exit(0)
		}
	}
}

type cvStats map[string]*cvStat

func (stats cvStats) get(s string) *cvStat {
	st := stats[s]
	if st == nil {
		st = &cvStat{minRTT: math.MaxInt64}
		stats[s] = st
	}
	return st
}

type cvStat struct {
	received    uint64
	transmitted uint64
	opErrors    uint64
	icmpErrors  uint64

	minRTT time.Duration
	maxRTT time.Duration
	rttSum time.Duration
	rttSq  float64
}

func (st *cvStat) onArrival(rtt time.Duration, r *ipoam.Report) {
	if r.Error != nil {
		st.opErrors++
		return
	}
	if r.ICMP.Type != ipv4.ICMPTypeEchoReply && r.ICMP.Type != ipv6.ICMPTypeEchoReply {
		st.icmpErrors++
		return
	}
	st.received++
	if rtt < st.minRTT {
		st.minRTT = rtt
	}
	if rtt > st.maxRTT {
		st.maxRTT = rtt
	}
	st.rttSum += rtt
	st.rttSq += float64(rtt) * float64(rtt)
}

func (st *cvStat) onDeparture(r *ipoam.Report) {
	st.transmitted++
	if r.Error != nil {
		st.opErrors++
	}
}

func printCVBanner(bw *bufio.Writer, dsts string, c *ipaddr.Cursor) {
	fmt.Fprintf(bw, "Connectivity verification for %s", dsts)
	if cvVerbose {
		fmt.Fprintf(bw, " [")
		printed := false
		for pos := c.First(); pos != nil; pos = c.Next() {
			if !cvIPv6only && pos.IP.To4() != nil || !cvIPv4only && pos.IP.To16() != nil && pos.IP.To4() == nil {
				if printed {
					fmt.Fprintf(bw, " ")
				}
				fmt.Fprintf(bw, "%v", pos.IP)
				printed = true
			} else {
				printed = false
			}
		}
		fmt.Fprintf(bw, "]")
		c.Reset(nil)
	}
	fmt.Fprintf(bw, ": %d bytes payload\n", len(cvPayload))
	bw.Flush()
}

func printCVReport(bw *bufio.Writer, rtt time.Duration, r *ipoam.Report) {
	if cvQuiet {
		return
	}
	if r.Error != nil {
		fmt.Fprintf(bw, "error=%q\n", r.Error)
		bw.Flush()
		return
	}
	if r.ICMP.Type != ipv4.ICMPTypeEchoReply && r.ICMP.Type != ipv6.ICMPTypeEchoReply {
		fmt.Fprintf(bw, "from=%s icmp.type=%q icmp.code=%d rtt=%v\n", literalOrName(r.Src.String(), cvNoRevLookup), r.ICMP.Type, r.ICMP.Code, rtt)
		bw.Flush()
		return
	}
	echo, _ := r.ICMP.Body.(*icmp.Echo)
	fmt.Fprintf(bw, "%d bytes", len(echo.Data))
	if !cvVerbose {
		fmt.Fprintf(bw, " from=%s echo.seq=%d rtt=%v\n", literalOrName(r.Src.String(), cvNoRevLookup), echo.Seq, rtt)
		bw.Flush()
		return
	}
	if r.Dst == nil {
		fmt.Fprintf(bw, " from=%s", literalOrName(r.Src.String(), cvNoRevLookup))
	} else {
		fmt.Fprintf(bw, " tc=%#x hops=%d from=%s to=%s", r.TC, r.Hops, literalOrName(r.Src.String(), cvNoRevLookup), literalOrName(r.Dst.String(), cvNoRevLookup))
	}
	if r.Interface != nil {
		fmt.Fprintf(bw, " if=%s", r.Interface.Name)
	}
	fmt.Fprintf(bw, " echo.id=%d echo.seq=%d rtt=%v\n", echo.ID, echo.Seq, rtt)
	bw.Flush()
}

func printCVSummary(bw *bufio.Writer, dsts string, stats cvStats) {
	fmt.Fprintf(bw, "\nStatistical information for %s:\n", dsts)
	for ip, st := range stats {
		var avg time.Duration
		var stddev float64
		if st.received > 0 {
			avg = st.rttSum / time.Duration(st.received)
			stddev = math.Sqrt(float64(st.rttSq)/float64(st.received) - float64(avg)*float64(avg))
		} else {
			st.minRTT = 0
		}
		fmt.Fprintf(bw, "%s:", literalOrName(ip, cvNoRevLookup))
		if st.transmitted > 0 && st.received <= st.transmitted {
			fmt.Fprintf(bw, " loss=%.1f%%", float64(st.transmitted-st.received)*100.0/float64(st.transmitted))
		}
		fmt.Fprintf(bw, " rcvd=%d sent=%d op.err=%d icmp.err=%d", st.received, st.transmitted, st.opErrors, st.icmpErrors)
		fmt.Fprintf(bw, " min=%v avg=%v max=%v stddev=%v\n", st.minRTT, avg, st.maxRTT, time.Duration(stddev))
	}
	bw.Flush()
}
