// Copyright 2014 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam

import (
	"errors"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// See golang.org/x/net/internal/iana.
	ianaProtocolICMP     = 1
	ianaProtocolIPv6ICMP = 58
)

type ipHeader interface {
	String() string
}

func parseICMPErrorMessage(m *icmp.Message) (ipHeader, *icmp.Message, error) {
	var b []byte
	switch body := m.Body.(type) {
	case *icmp.DstUnreach:
		b = body.Data
	case *icmp.PacketTooBig:
		b = body.Data
	case *icmp.TimeExceeded:
		b = body.Data
	case *icmp.ParamProb:
		b = body.Data
	}
	if len(b) == 0 {
		return nil, nil, errors.New("non-icmp error message")
	}
	var iph ipHeader
	switch m.Type {
	case ipv4.ICMPTypeDestinationUnreachable, ipv4.ICMPTypeTimeExceeded, ipv4.ICMPTypeParameterProblem:
		h, err := icmp.ParseIPv4Header(b)
		if err != nil {
			return nil, nil, err
		}
		b = b[ipv4.HeaderLen+len(h.Options):]
		iph = h
	case ipv6.ICMPTypeDestinationUnreachable, ipv6.ICMPTypePacketTooBig, ipv6.ICMPTypeTimeExceeded, ipv6.ICMPTypeParameterProblem:
		h, err := ipv6.ParseHeader(b)
		if err != nil {
			return nil, nil, err
		}
		b = b[ipv6.HeaderLen:]
		iph = h
	default:
		return nil, nil, errors.New("non-icmp error message")
	}
	m, err := icmp.ParseMessage(m.Type.Protocol(), b)
	if err != nil {
		return nil, nil, err
	}
	return iph, m, nil
}

func reachable(tgt, fm net.Addr) bool {
	var ip net.IP
	var ipn *net.IPNet
	switch tgt := tgt.(type) {
	case *net.IPNet:
		ipn, ip = tgt, tgt.IP
	case *net.TCPAddr:
		ip = tgt.IP
	case *net.UDPAddr:
		ip = tgt.IP
	case *net.IPAddr:
		ip = tgt.IP
	default:
		return false
	}
	if ip.IsMulticast() {
		return true
	}
	switch fm := fm.(type) {
	case *net.TCPAddr:
		if ipn != nil {
			return ipn.Contains(fm.IP)
		}
		return ip.Equal(fm.IP)
	case *net.UDPAddr:
		if ipn != nil {
			return ipn.Contains(fm.IP)
		}
		return ip.Equal(fm.IP)
	case *net.IPAddr:
		if ipn != nil {
			return ipn.Contains(fm.IP)
		}
		return ip.Equal(fm.IP)
	default:
		return false
	}
}
