// Copyright 2014 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// A ControlMessage contains per packet basis probe options.
type ControlMessage struct {
	ID   int // ICMP echo identifier
	Seq  int // ICMP echo sequence number
	Port int // UDP destination port
}

// A Tester represents a tester for IP-layer OAM.
type Tester struct {
	initOnce sync.Once
	pconn    *conn // probe connection
	mconn    *conn // maintenance connection
	*maint         // maintenance endpoint
}

func (t *Tester) init() {
	go t.monitor(t.mconn)
}

// IPv4PacketConn returns the ipv4.PacketConn of the probe network
// connection.
// It returns nil when t is not created as a tester using IPv4.
func (t *Tester) IPv4PacketConn() *ipv4.PacketConn {
	return t.pconn.p4
}

// IPv6PacketConn returns the ipv6.PacketConn of the probe network
// connection.
// It returns nil when t is not created as a tester using IPv6.
func (t *Tester) IPv6PacketConn() *ipv6.PacketConn {
	return t.pconn.p6
}

// Close closes both the maintenance and probe network connections.
func (t *Tester) Close() error {
	if t == nil || t.pconn == nil || t.mconn == nil {
		return syscall.EINVAL
	}
	perr := t.pconn.close()
	if t.pconn == t.mconn {
		return perr
	}
	merr := t.mconn.close()
	if perr != nil {
		return perr
	}
	return merr
}

// Probe transmits a single probe packet to ip via ifi.
// Each call updates the internal receive packet filter on the
// maintenance network connection automatically.
func (t *Tester) Probe(b []byte, cm *ControlMessage, ip net.IP, ifi *net.Interface) error {
	t.initOnce.Do(t.init)

	var zone string
	if ifi != nil {
		zone = ifi.Name
	}
	if cm == nil {
		cm = &ControlMessage{ID: os.Getpid() & 0xffff, Seq: 1, Port: 33434}
	}
	var dst net.Addr
	if !t.pconn.rawSocket {
		dst = &net.UDPAddr{IP: ip, Port: cm.Port, Zone: zone}
		t.setUDPCookie(ianaProtocolUDP, t.pconn.sport, cm.Port)
	} else {
		dst = &net.IPAddr{IP: ip, Zone: zone}
	}

	switch t.pconn.protocol {
	case ianaProtocolUDP:
		_, err := t.pconn.writeTo(b, dst, ifi)
		return err
	case ianaProtocolICMP, ianaProtocolIPv6ICMP:
		echo := icmp.Echo{ID: cm.ID, Seq: cm.Seq, Data: b}
		t.setICMPCookie(t.pconn.protocol, echo.ID, echo.Seq)
		m := icmp.Message{Code: 0, Body: &echo}
		if ip.To4() != nil {
			m.Type = ipv4.ICMPTypeEcho
		}
		if ip.To16() != nil && ip.To4() == nil {
			m.Type = ipv6.ICMPTypeEchoRequest
		}
		b, err := m.Marshal(nil)
		if err != nil {
			return err
		}
		if ip.IsMulticast() && ifi != nil {
			var err error
			if t.pconn.protocol == ianaProtocolICMP {
				err = t.pconn.p4.SetMulticastInterface(ifi)
			}
			if t.pconn.protocol == ianaProtocolIPv6ICMP {
				err = t.pconn.p6.SetMulticastInterface(ifi)
			}
			if err != nil {
				return err
			}
		}
		_, err = t.pconn.writeTo(b, dst, ifi)
		return err
	default:
		return fmt.Errorf("unknown protocol: %d", t.pconn.protocol)
	}
}

// NewTester makes both maintenance and probe network connections and
// listens for incoming ICMP packets addressed to the address on the
// maintenance network connection.
// The network must specify a probe network.
// It must be "ip4:icmp", "ip4:1", "ip6:ipv6-icmp", "ip6:58", "udp",
// "udp4" or "udp6".
//
// Examples:
//	NewTester("ip4:icmp", "0.0.0.0")
//	NewTester("udp", "0.0.0.0")
//	NewTester("ip6:58", "2001:db8::1")
func NewTester(network, address string) (*Tester, error) {
	t := Tester{maint: &maint{emitReport: 1, report: make(chan Report, 1)}}

	var err error
	t.pconn, err = newProbeConn(network, address)
	if err != nil {
		return nil, err
	}

	switch network {
	case "ip4:icmp", "ip4:1":
		if t.pconn.p4 != nil {
			t.mconn = t.pconn
		} else {
			t.mconn, err = newMaintConn(network, t.pconn.ip.String())
			if err != nil {
				t.pconn.close()
				return nil, err
			}
		}
	case "ip6:ipv6-icmp", "ip6:58":
		t.mconn = t.pconn
	case "udp":
		t.mconn, err = newMaintConn("ip4:icmp+ip6:ipv6-icmp", t.pconn.ip.String())
		if err != nil {
			t.pconn.close()
			return nil, err
		}
	case "udp4":
		t.mconn, err = newMaintConn("ip4:icmp", t.pconn.ip.String())
		if err != nil {
			t.pconn.close()
			return nil, err
		}
	case "udp6":
		t.mconn, err = newMaintConn("ip6:ipv6-icmp", t.pconn.ip.String())
		if err != nil {
			t.pconn.close()
			return nil, err
		}
	default:
		t.pconn.close()
		return nil, net.UnknownNetworkError(network)
	}

	if t.mconn.ip.To4() != nil {
		if runtime.GOOS == "linux" {
			var f ipv4.ICMPFilter
			f.SetAll(true)
			f.Accept(ipv4.ICMPTypeEchoReply)
			f.Accept(ipv4.ICMPTypeDestinationUnreachable)
			f.Accept(ipv4.ICMPTypeTimeExceeded)
			f.Accept(ipv4.ICMPTypeParameterProblem)
			if t.mconn.r4 != nil {
				t.mconn.r4.SetICMPFilter(&f)
			} else {
				t.mconn.p4.SetICMPFilter(&f)
			}
		}
		f := ipv4.FlagSrc | ipv4.FlagDst | ipv4.FlagInterface
		if runtime.GOOS != "solaris" {
			// It looks like IP_RECVTTL doesn't work well
			// on Solaris.
			f |= ipv4.FlagTTL
		}
		if t.mconn.r4 != nil {
			t.mconn.r4.SetControlMessage(f, true)
		} else {
			t.mconn.p4.SetControlMessage(f, true)
		}
	}
	if t.mconn.ip.To16() != nil && t.mconn.ip.To4() == nil {
		var f ipv6.ICMPFilter
		f.SetAll(true)
		f.Accept(ipv6.ICMPTypeEchoReply)
		f.Accept(ipv6.ICMPTypeDestinationUnreachable)
		f.Accept(ipv6.ICMPTypePacketTooBig)
		f.Accept(ipv6.ICMPTypeTimeExceeded)
		f.Accept(ipv6.ICMPTypeParameterProblem)
		t.mconn.p6.SetICMPFilter(&f)
		t.mconn.p6.SetControlMessage(ipv6.FlagTrafficClass|ipv6.FlagHopLimit|ipv6.FlagSrc|ipv6.FlagDst|ipv6.FlagInterface, true)
	}
	return &t, nil
}
