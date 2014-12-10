// Copyright 2014 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam

import (
	"net"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// A LoopbackReport represents a report of loopback test.
type LoopbackReport struct {
	Addr      net.Addr      // target address
	RTT       time.Duration // round-trip time
	ICMPError *icmp.Message // received icmp error message
}

// A Loopback represents a loopback test configuration.
type Loopback struct {
	LocalAddr string         // listening address
	Interface *net.Interface // outbound interface
	Timeout   time.Duration  // timeout, default value is 3 seconds
}

// Run starts the loopback test and waits for it to complete.
func (lb *Loopback) Run(echo *icmp.Echo, tgt net.Addr) (*LoopbackReport, error) {
	lbt := loopbackTest{Loopback: *lb}
	if err := lbt.parse(tgt); err != nil {
		return nil, err
	}
	var lastErr, err error
	var c *icmp.PacketConn
	for _, network := range lbt.networks {
		c, err = icmp.ListenPacket(network, lbt.Loopback.LocalAddr)
		if err != nil {
			lastErr = err
			continue
		}
		break
	}
	if c == nil {
		return nil, lastErr
	}
	defer c.Close()
	m := icmp.Message{Type: lbt.Type, Code: 0, Body: echo}
	return lbt.roundTrip(c, &m, tgt)
}

type loopbackTest struct {
	Loopback

	networks []string
	net.IP
	zone string
	icmp.Type
	tmo time.Duration
}

func (lbt *loopbackTest) parse(dst net.Addr) error {
	lbt.tmo = lbt.Loopback.Timeout
	if lbt.tmo == 0 {
		lbt.tmo = 3 * time.Second
	}
	fn := func(ip net.IP, zone string) error {
		if ip.To4() != nil {
			lbt.IP, lbt.zone, lbt.Type = ip, zone, ipv4.ICMPTypeEcho
			lbt.networks = []string{"ip4:icmp", "udp4"}
			return nil
		}
		if ip.To16() != nil && ip.To4() == nil {
			lbt.IP, lbt.zone, lbt.Type = ip, zone, ipv6.ICMPTypeEchoRequest
			lbt.networks = []string{"ip6:ipv6-icmp", "udp6"}
			return nil
		}
		return net.InvalidAddrError("neither ipv4 nor ipv6 address")
	}
	switch a := dst.(type) {
	case *net.IPNet:
		return fn(a.IP.Mask(a.Mask), "")
	case *net.TCPAddr:
		return fn(a.IP, a.Zone)
	case *net.UDPAddr:
		return fn(a.IP, a.Zone)
	case *net.IPAddr:
		return fn(a.IP, a.Zone)
	default:
		return net.InvalidAddrError("doesn't implement net.Addr interface")
	}
}

func (lbt *loopbackTest) roundTrip(c *icmp.PacketConn, wm *icmp.Message, tgt net.Addr) (*LoopbackReport, error) {
	var dst net.Addr
	switch c.LocalAddr().(type) {
	case *net.UDPAddr:
		dst = &net.UDPAddr{IP: lbt.IP, Zone: lbt.zone}
	case *net.IPAddr:
		dst = &net.IPAddr{IP: lbt.IP, Zone: lbt.zone}
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return nil, err
	}
	begin := time.Now()
	switch wm.Type.Protocol() {
	case ianaProtocolICMP:
		p := c.IPv4PacketConn()
		if p != nil && runtime.GOOS == "linux" {
			var f ipv4.ICMPFilter
			f.SetAll(true)
			f.Accept(ipv4.ICMPTypeEchoReply)
			f.Accept(ipv4.ICMPTypeDestinationUnreachable)
			f.Accept(ipv4.ICMPTypeTimeExceeded)
			f.Accept(ipv4.ICMPTypeParameterProblem)
			p.SetICMPFilter(&f)
		}
		if p != nil && lbt.IP.IsMulticast() && lbt.Loopback.Interface != nil {
			p.SetMulticastInterface(lbt.Loopback.Interface)
		}
		_, err = c.WriteTo(wb, dst)
	case ianaProtocolIPv6ICMP:
		cm := ipv6.ControlMessage{}
		p := c.IPv6PacketConn()
		if p != nil {
			var f ipv6.ICMPFilter
			f.SetAll(true)
			f.Accept(ipv6.ICMPTypeEchoReply)
			f.Accept(ipv6.ICMPTypeDestinationUnreachable)
			f.Accept(ipv6.ICMPTypePacketTooBig)
			f.Accept(ipv6.ICMPTypeTimeExceeded)
			f.Accept(ipv6.ICMPTypeParameterProblem)
			p.SetICMPFilter(&f)
			if lbt.Loopback.Interface != nil {
				cm.IfIndex = lbt.Loopback.Interface.Index
			}
			_, err = p.WriteTo(wb, &cm, dst)
		} else {
			_, err = c.WriteTo(wb, dst)
		}
	}
	if err != nil {
		return nil, err
	}
	rb := make([]byte, 128+len(wm.Body.(*icmp.Echo).Data))
	if err := c.SetReadDeadline(time.Now().Add(lbt.tmo)); err != nil {
		return nil, err
	}
	for {
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			return nil, err
		}
		rtt := time.Since(begin)
		rm, err := icmp.ParseMessage(wm.Type.Protocol(), rb[:n])
		if err != nil {
			return nil, err
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			// Please be informed that non-privileged
			// datagram-oriented ICMP endpoints override
			// icmp.Echo.ID when tranmitting packets.
			if reachable(tgt, peer) && wm.Body.(*icmp.Echo).Seq == rm.Body.(*icmp.Echo).Seq {
				return &LoopbackReport{Addr: peer, RTT: rtt}, nil
			}
		default:
			_, m, err := parseICMPErrorMessage(rm)
			if err == nil && m.Type == wm.Type {
				return &LoopbackReport{Addr: peer, RTT: rtt, ICMPError: rm}, nil
			}
		}
	}
}
