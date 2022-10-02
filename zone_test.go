package dns

import (
	"net/netip"
	"testing"
)

func TestReadZonefile(t *testing.T) {
	zone, err := ReadZonefile("testdata/example.com.zone")
	if err != err {
		t.Error(err)
	}
	if zone.Origin != "example.com." {
		t.Error("zone.Origin != \"example.com.\"")
	}
	if zone.TTL != 3600 {
		t.Error("zone.TTL != 3600")
	}

	// A record
	if zone.Records[0].Name != "example.com." {
		t.Error(zone.Records[0].Name)
	}
	if zone.Records[0].Type != TypeA {
		t.Error(zone.Records[0].Type)
	}
	if zone.Records[0].TTL != 600 {
		t.Error(zone.Records[0].TTL)
	}
	if zone.Records[0].RData.(A) != netip.MustParseAddr("192.0.2.1") {
		t.Error(zone.Records[0].RData)
	}
	if zone.Records[2].Name != "mx1.example.com." {
		t.Error(zone.Records[2].Name)
	}
	if zone.Records[2].Type != TypeA {
		t.Error(zone.Records[2].Type)
	}
	if zone.Records[2].TTL != 3600 {
		t.Error(zone.Records[2].TTL)
	}
	if zone.Records[2].RData.(A) != netip.MustParseAddr("192.0.2.3") {
		t.Error(zone.Records[2].RData)
	}

	// MX record
	if zone.Records[4].Name != "example.com." {
		t.Error(zone.Records[4].Name)
	}
	if zone.Records[4].Type != TypeMX {
		t.Error(zone.Records[4].Type)
	}
	if zone.Records[4].TTL != 3600 {
		t.Error(zone.Records[4].TTL)
	}
	if zone.Records[4].RData.(MX).String() != "10 mx1.example.com." {
		t.Error(zone.Records[4].RData)
	}
}
