// Copyright 2014 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam_test

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/mikioh/ipoam"
)

var testerGlobalUnicastTests = []struct {
	network, address, dst string
}{
	{"ip4:icmp", "0.0.0.0", "golang.org"},
	{"udp", "0.0.0.0:0", "golang.org"},

	{"ip6:ipv6-icmp", "::", "golang.org"},
	{"udp", "[::]:0", "golang.org"},

	{"ip4:icmp", "0.0.0.0", "www.google.com"},
	{"udp", "0.0.0.0:0", "www.google.com"},

	{"ip6:ipv6-icmp", "::", "www.google.com"},
	{"udp", "[::]:0", "www.google.com"},
}

func TestTesterGlobalUnicast(t *testing.T) {
	if testing.Short() {
		t.Skip("to avoid external network")
	}

	for i, tt := range testerGlobalUnicastTests {
		cm := ipoam.ControlMessage{ID: os.Getpid()&0xffff + i, Port: 33434}
		ipt, err := ipoam.NewTester(tt.network, tt.address)
		if err != nil {
			t.Fatal(err)
		}
		defer ipt.Close()

		ips, err := net.LookupIP(tt.dst)
		if err != nil {
			t.Error(err)
			continue
		}
		nips := ips[:0]
		for _, ip := range ips {
			if ip.To4() != nil && ipt.IPv4PacketConn() != nil || ip.To16() != nil && ip.To4() == nil && ipt.IPv6PacketConn() != nil {
				nips = append(nips, ip)
			}
		}
		ips = nips

		cm.Seq = i + 1
		for _, ip := range ips {
			if err := ipt.Probe([]byte("HELLO-R-U-THERE"), &cm, ip, nil); err != nil {
				t.Log(err)
			}
		}

		wait := time.NewTimer(250 * time.Millisecond)
		var rs []ipoam.Report
	loop:
		for {
			select {
			case <-wait.C:
				break loop
			case r := <-ipt.Report():
				rs = append(rs, r)
			}
		}
		wait.Stop()

		if len(rs) == 0 {
			t.Logf("got no records for %s on %s, %s", tt.dst, tt.network, tt.address)
		}
		for _, r := range rs {
			if r.Error != nil {
				t.Logf("%s: %v", tt.dst, r.Error)
			}
			if r.ICMP != nil {
				t.Logf("%s: %+v", tt.dst, r.ICMP)
			}
		}
	}
}

var testerLinkLocalMulticastTests = []struct {
	network, address string
	ip               net.IP
}{
	{"ip4:icmp", "0.0.0.0", net.IPv4(224, 0, 0, 251)},

	{"ip6:ipv6-icmp", "::", net.ParseIP("ff02::1")},
}

func TestTesterLinkLocalMulticast(t *testing.T) {
	if testing.Short() {
		t.Skip("to avoid external network")
	}

	ift, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	mift := ift[:0]
	for _, ifi := range ift {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		mift = append(mift, ifi)
	}

	for i, tt := range testerLinkLocalMulticastTests {
		cm := ipoam.ControlMessage{ID: os.Getpid()&0xffff + i}
		ipt, err := ipoam.NewTester(tt.network, tt.address)
		if err != nil {
			t.Fatal(err)
		}
		defer ipt.Close()

		cm.Seq = i + 1
		for j := range mift {
			if err := ipt.Probe([]byte("HELLO-R-U-THERE"), &cm, tt.ip, &mift[j]); err != nil {
				t.Log(err)
			}
		}

		wait := time.NewTimer(250 * time.Millisecond)
		var rs []ipoam.Report
	loop:
		for {
			select {
			case <-wait.C:
				break loop
			case r := <-ipt.Report():
				rs = append(rs, r)
			}
		}
		wait.Stop()

		if len(rs) == 0 {
			t.Logf("got no records for %v on %s, %s", tt.ip, tt.network, tt.address)
		}
		for _, r := range rs {
			if r.Error != nil {
				t.Logf("%v: %v", tt.ip, r.Error)
			}
			if r.ICMP != nil {
				t.Logf("%v: %+v", tt.ip, r.ICMP)
			}
		}
	}
}
