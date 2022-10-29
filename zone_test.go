package dns

import (
	"net/netip"
	"testing"
)

func TestReadZonefile(t *testing.T) {
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

	var data = map[int]ResourceRecord{
		0:  {"example.com.", TypeNS, ClassIN, 3600, NS("ns1.example.com.")},
		2:  {"example.com.", TypeA, ClassIN, 600, A(netip.MustParseAddr("192.0.2.1"))},
		4:  {"www.example.com.", TypeCNAME, ClassIN, 3600, CNAME("example.com.")},
		5:  {"mx1.example.com.", TypeA, ClassIN, 3600, A(netip.MustParseAddr("192.0.2.3"))},
		7:  {"example.com.", TypeMX, ClassIN, 3600, MX{10, "mx1.example.com."}},
		9:  {"example.com.", TypeTXT, ClassIN, 3600, TXT("foo\x00bar")},
		10: {"example.com.", TypeAAAA, ClassIN, 600, AAAA(netip.MustParseAddr("2001:db8::1"))},
	}
	for k, v := range data {
		if v != zone.Records[k] {
			t.Error(zone.Records[k])
		}
	}
}
