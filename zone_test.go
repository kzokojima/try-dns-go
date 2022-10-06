package dns

import (
	"net/netip"
	"testing"
)

func TestReadZonefile(t *testing.T) {
	var expected ResourceRecord

	zone, err := ReadZonefile("testdata/zones/example.com.zone")
	if err != nil {
		t.Fatal(err)
	}
	if zone.Origin != "example.com." {
		t.Error("zone.Origin != \"example.com.\"")
	}
	if zone.TTL != 3600 {
		t.Error("zone.TTL != 3600")
	}

	// NS record
	expected = ResourceRecord{"example.com.", TypeNS, ClassIN, 3600, NS("ns1.example.com.")}
	if expected != zone.Records[0] {
		t.Error(zone.Records[0])
	}

	// A record
	expected = ResourceRecord{"example.com.", TypeA, ClassIN, 600, netip.MustParseAddr("192.0.2.1")}
	if expected != zone.Records[2] {
		t.Error(zone.Records[2])
	}
	expected = ResourceRecord{"mx1.example.com.", TypeA, ClassIN, 3600, netip.MustParseAddr("192.0.2.3")}
	if expected != zone.Records[4] {
		t.Error(zone.Records[4])
	}

	// MX record
	expected = ResourceRecord{"example.com.", TypeMX, ClassIN, 3600, MX{10, "mx1.example.com."}}
	if expected != zone.Records[6] {
		t.Error(zone.Records[6])
	}
}
