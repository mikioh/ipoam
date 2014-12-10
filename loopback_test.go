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
	"golang.org/x/net/icmp"
	"golang.org/x/net/internal/nettest"
)

var loopbackGlobalUnicastTests = []struct {
	target string
}{
	{"www.google.com"},
	{"golang.org"},
}

func TestLoopbackGlobalUnicast(t *testing.T) {
	for _, tt := range loopbackGlobalUnicastTests {
		ips, err := net.LookupIP(tt.target)
		if err != nil {
			t.Error(err)
			continue
		}

		var errs []error
		var lrs []*ipoam.LoopbackReport
		for i, ip := range ips {
			lb := ipoam.Loopback{Timeout: 5 * time.Second}
			echo := icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  i + 1,
				Data: []byte("HELLO-R-U-THERE"),
			}
			lr, err := lb.Run(&echo, &net.IPAddr{IP: ip})
			if err != nil {
				errs = append(errs, err)
				continue
			}
			lrs = append(lrs, lr)
		}

		for _, lr := range lrs {
			t.Logf("%+v", lr)
		}
		for _, err := range errs {
			if len(lrs) == 0 {
				t.Error(err)
			} else {
				t.Log(err)
			}
		}
	}
}

var loopbackMulticastTests = []struct {
	network string
	target  net.Addr
}{
	{"ip4", &net.IPAddr{IP: net.IPv4(224, 0, 0, 251)}},

	{"ip6", &net.IPAddr{IP: net.ParseIP("ff02::1")}},
}

func TestLoopbackMulticast(t *testing.T) {
	if testing.Short() {
		t.Skip("to avoid external network")
	}

	for _, tt := range loopbackMulticastTests {
		ifi := nettest.RoutedInterface(tt.network, net.FlagUp|net.FlagBroadcast|net.FlagMulticast)
		if ifi == nil {
			continue
		}
		lb := ipoam.Loopback{
			Timeout:   5 * time.Second,
			Interface: ifi,
		}
		echo := icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("HELLO-R-U-THERE"),
		}
		lr, err := lb.Run(&echo, tt.target)
		if err != nil {
			t.Error(err)
			continue
		}
		t.Logf("%+v", lr)
	}
}
