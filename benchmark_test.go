// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam_test

import (
	"net"
	"os"
	"testing"

	"github.com/mikioh/ipoam"
)

func BenchmarkTesterGoogleIPv4(b *testing.B) {
	ipt, err := ipoam.NewTester("ip4:icmp", "0.0.0.0")
	if err != nil {
		b.Fatal(err)
	}
	defer ipt.Close()
	ips, err := net.LookupIP("ipv4.google.com")
	if err != nil {
		b.Fatal(err)
	}
	benchmarkLoopbackGoogle(b, ipt, ips[0])
}

func BenchmarkTesterGoogleIPv6(b *testing.B) {
	ipt, err := ipoam.NewTester("ip6:ipv6-icmp", "::")
	if err != nil {
		b.Fatal(err)
	}
	defer ipt.Close()
	ips, err := net.LookupIP("ipv6.google.com")
	if err != nil {
		b.Fatal(err)
	}
	benchmarkLoopbackGoogle(b, ipt, ips[0])
}

func benchmarkLoopbackGoogle(b *testing.B, ipt *ipoam.Tester, ip net.IP) {
	cm := ipoam.ControlMessage{ID: os.Getpid() & 0xffff}
	for i := 0; i < b.N; i++ {
		cm.Seq = i + 1
		if err := ipt.Probe([]byte("HELLO-R-U-THERE"), &cm, ip, nil); err != nil {
			b.Fatal(err)
		}
		<-ipt.Report()
	}
}
