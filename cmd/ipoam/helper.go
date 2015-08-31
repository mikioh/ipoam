// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"strings"
	"time"

	"github.com/mikioh/ipaddr"
	"github.com/mikioh/ipoam"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func parseDsts(s string, ipv4only, ipv6only bool) (*ipaddr.Cursor, *net.Interface, error) {
	var ifi *net.Interface
	var ps []ipaddr.Prefix
	ss := strings.Split(s, ",")

	for _, s := range ss {
		if strings.Contains(s, "%") {
			ipa, err := net.ResolveIPAddr("ip", s)
			if err == nil {
				if ifi == nil {
					ifi, _ = net.InterfaceByName(ipa.Zone)
				}
				ps = append(ps, *newPrefix(ipa.IP))
				continue
			}
		}
		ips, err := net.LookupIP(s)
		if err == nil {
			for _, ip := range ips {
				ps = append(ps, *newPrefix(ip))
			}
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err == nil {
			ps = append(ps, *ipaddr.NewPrefix(n))
			continue
		}
		ip := net.ParseIP(s)
		if ip != nil {
			ps = append(ps, *newPrefix(ip))
			continue
		}
	}
	if len(ps) == 0 {
		return nil, nil, &net.AddrError{Err: "failed to resolve", Addr: s}
	}

	c := ipaddr.NewCursor(ps)
	var multi, uni bool
	for pos := c.First(); pos != nil; pos = c.Next() {
		if !ipv6only && pos.IP.To4() != nil {
			if pos.IP.IsMulticast() {
				multi = true
			} else {
				uni = true
			}
		}
		if !ipv4only && pos.IP.To16() != nil && pos.IP.To4() == nil {
			if pos.IP.IsMulticast() {
				multi = true
			} else {
				uni = true
			}
		}
		if multi && uni {
			return nil, nil, &net.AddrError{Err: "prohibited from mixing unicast and multicast destinations", Addr: s}
		}
	}
	c.Reset(nil)
	return c, ifi, nil
}

func newPrefix(ip net.IP) *ipaddr.Prefix {
	var p ipaddr.Prefix
	p.IP = ip
	if p.IP.To4() != nil {
		p.Mask = net.CIDRMask(ipaddr.IPv4PrefixLen, ipaddr.IPv4PrefixLen)
	}
	if p.IP.To16() != nil && p.IP.To4() == nil {
		p.Mask = net.CIDRMask(ipaddr.IPv6PrefixLen, ipaddr.IPv6PrefixLen)
	}
	return &p
}

func revLookup(address string) string {
	type racer struct {
		names []string
		error
	}
	lane := make(chan racer, 1)
	go func() {
		names, err := net.LookupAddr(address)
		lane <- racer{names, err}
	}()
	t := time.NewTimer(500 * time.Millisecond)
	defer t.Stop()
	select {
	case <-t.C:
		return ""
	case r := <-lane:
		if r.error != nil {
			return ""
		}
		return r.names[0]
	}
}

func hasReached(r *ipoam.Report) bool {
	if r.Error != nil || r.ICMP == nil {
		return false
	}
	switch r.ICMP.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		return true
	case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
		return true
	}
	return false
}
