package main

import (
	"net/netip"
	"testing"
)

func TestArpaName(t *testing.T) {
	expanded, err := arpaName("2001:db8::1")
	if err != nil {
		t.Error(err)
	}
	if expanded != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Error(expanded)
	}
}

func TestDefaultNameServer(t *testing.T) {
	server, err := defaultNameServer()
	if err != nil {
		t.Error(err)
	}
	_, err = netip.ParseAddr(server)
	if err != nil {
		t.Error(server)
	}
}
