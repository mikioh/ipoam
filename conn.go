// Copyright 2014 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// See golang.org/x/net/internal/iana.
	ianaProtocolIP       = 0
	ianaProtocolICMP     = 1
	ianaProtocolUDP      = 17
	ianaProtocolIPv6     = 41
	ianaProtocolIPv6ICMP = 58
)

// A conn represents a connection endpoint.
type conn struct {
	protocol  int            // protocol number
	rawSocket bool           // true if c is a raw socket
	ip        net.IP         // local address of c
	sport     int            // source port of c
	c         net.PacketConn // net.IPConn, net.UDPConn or icmp.PacketConn
	r4        *ipv4.RawConn
	p4        *ipv4.PacketConn
	p6        *ipv6.PacketConn
}

func (c *conn) close() error {
	if c == nil || c.c == nil {
		return syscall.EINVAL
	}
	return c.c.Close()
}

func (c *conn) readFrom(b []byte) ([]byte, interface{}, interface{}, net.Addr, error) {
	if !c.rawSocket {
		n, peer, err := c.c.ReadFrom(b)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return b[:n], nil, nil, peer, nil
	}
	switch c.protocol {
	case ianaProtocolICMP:
		if c.r4 != nil {
			h, p, cm, err := c.r4.ReadFrom(b)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			return p, h, cm, &net.IPAddr{IP: cm.Src}, nil
		}
		n, cm, peer, err := c.p4.ReadFrom(b)
		return b[:n], nil, cm, peer, err
	case ianaProtocolIPv6ICMP:
		n, cm, peer, err := c.p6.ReadFrom(b)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return b[:n], nil, cm, peer, err
	default:
		return nil, nil, nil, nil, fmt.Errorf("unknown protocol: %d", c.protocol)
	}
}

func (c *conn) setup(maint bool) {
	switch la := c.c.LocalAddr().(type) {
	case *net.UDPAddr:
		c.ip = la.IP
		c.sport = la.Port
	case *net.IPAddr:
		c.rawSocket = true
		c.ip = la.IP
	}
	if c.rawSocket {
		switch c.protocol {
		case ianaProtocolICMP:
			if maint {
				c.r4, _ = ipv4.NewRawConn(c.c)
			} else {
				c.p4 = ipv4.NewPacketConn(c.c)
			}
		case ianaProtocolIPv6ICMP:
			c.p6 = ipv6.NewPacketConn(c.c)
		}
	} else {
		switch c.protocol {
		case ianaProtocolICMP, ianaProtocolIPv6ICMP:
			if c.ip.To4() != nil {
				c.p4 = c.c.(*icmp.PacketConn).IPv4PacketConn()
			}
			if c.ip.To16() != nil && c.ip.To4() == nil {
				c.p6 = c.c.(*icmp.PacketConn).IPv6PacketConn()
			}
		case ianaProtocolUDP:
			if c.ip.To4() != nil {
				c.p4 = ipv4.NewPacketConn(c.c)
			}
			if c.ip.To16() != nil && c.ip.To4() == nil {
				c.p6 = ipv6.NewPacketConn(c.c)
			}
		}
	}
}

func (c *conn) writeTo(b []byte, dst net.Addr, ifi *net.Interface) (int, error) {
	if !c.rawSocket {
		return c.c.WriteTo(b, dst)
	}
	switch c.protocol {
	case ianaProtocolICMP:
		var cm *ipv4.ControlMessage
		if ifi != nil {
			cm = &ipv4.ControlMessage{IfIndex: ifi.Index}
		}
		if c.r4 != nil {
			h := &ipv4.Header{
				Version:  ipv4.Version,
				Len:      ipv4.HeaderLen,
				TotalLen: ipv4.HeaderLen + len(b),
				Protocol: ianaProtocolICMP,
				Dst:      dst.(*net.IPAddr).IP,
			}
			if err := c.r4.WriteTo(h, b, cm); err != nil {
				return 0, err
			}
			return len(b), nil
		}
		return c.p4.WriteTo(b, cm, dst)
	case ianaProtocolIPv6ICMP:
		var cm *ipv6.ControlMessage
		if ifi != nil {
			cm = &ipv6.ControlMessage{IfIndex: ifi.Index}
		}
		return c.p6.WriteTo(b, cm, dst)
	default:
		return 0, fmt.Errorf("unknown protocol: %d", c.protocol)
	}
}

func newProbeConn(network, address string) (*conn, error) {
	var err error
	var c *conn
	switch network {
	case "ip4:icmp", "ip4:1", "ip6:ipv6-icmp", "ip6:58":
		c, err = newICMPConn(network, address)
	case "udp", "udp4", "udp6":
		c, err = newUDPConn(network, address)
	default:
		return nil, net.UnknownNetworkError(network)
	}
	if err != nil {
		return nil, err
	}
	c.setup(false)
	return c, nil
}

func newMaintConn(network, address string) (*conn, error) {
	var err error
	var c *conn
	switch network {
	case "ip4:icmp", "ip4:1", "ip6:ipv6-icmp", "ip6:58", "ip4:icmp+ip6:ipv6-icmp":
		c, err = newICMPConn(network, address)
	default:
		return nil, net.UnknownNetworkError(network)
	}
	if err != nil {
		return nil, err
	}
	c.setup(true)
	return c, nil
}

func newICMPConn(network, address string) (*conn, error) {
	ipa, err := net.ResolveIPAddr("ip", address)
	if err != nil {
		return nil, err
	}
	if ipa.IP == nil {
		switch network {
		case "ip4:icmp", "ip4:1", "ip4:icmp+ip6:ipv6-icmp":
			ipa.IP = net.IPv4zero
		case "ip6:ipv6-icmp", "ip6:58":
			ipa.IP = net.IPv6unspecified
		}
	}
	var conn conn
	var networks []string
	if ipa.IP.To4() != nil {
		networks = []string{"ip4:icmp", "udp4"}
		conn.protocol = ianaProtocolICMP
	}
	if ipa.IP.To16() != nil && ipa.IP.To4() == nil {
		networks = []string{"ip6:ipv6-icmp", "udp6"}
		conn.protocol = ianaProtocolIPv6ICMP
	}
	conn.c, err = net.ListenPacket(networks[0], address)
	if err != nil {
		conn.c, err = icmp.ListenPacket(networks[1], address)
		if err != nil {
			return nil, err
		}
	}
	return &conn, nil
}

func newUDPConn(network, address string) (*conn, error) {
	c, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return &conn{protocol: ianaProtocolUDP, c: c}, nil
}
