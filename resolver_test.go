package dns

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

func TestResolve(t *testing.T) {
	var rrs []ResourceRecord
	var err error
	rootServer = "198.41.0.4"

	domains := []string{"example.com.", "www.example.com."}
	for _, v := range domains {
		rrs, err := Resolve(Question{Name(v), TypeA, ClassIN}, true, NewMockClient(), nil)
		if err != nil {
			t.Errorf("%v %v", err, v)
		}
		if err == nil && rrs[0].RData.String() != "93.184.216.34" {
			t.Errorf("%v %v", rrs[0].RData.String(), v)
		}
	}

	rrs, err = Resolve(Question{Name("jprs.co.jp."), TypeA, ClassIN}, true, NewMockClient(), nil)
	if err != nil {
		t.Errorf("%v %v", err, "jprs.co.jp.")
	}
	if err == nil && rrs[0].RData.String() != "117.104.133.165" {
		t.Errorf("%v %v", rrs[0].RData.String(), "jprs.co.jp.")
	}
}

type MockClientDataKey struct {
	address  string
	question Question
}
type MockClient struct {
	data sync.Map
}

func NewMockClient() *MockClient {
	var data sync.Map

	storeData := func(address string, question Question, answers, authorities, additionals []ResourceRecord) {
		response, _ := MakeResponse(0, 0, question, answers, authorities, additionals)
		data.Store(MockClientDataKey{address, question}, response)
	}

	// com.
	storeData("198.41.0.4:53", Question{Name("com."), QNameMinType, ClassIN},
		nil,
		[]ResourceRecord{
			{Name("com."), TypeNS, ClassIN, 172800, NS("a.gtld-servers.net.")},
			{Name("com."), TypeNS, ClassIN, 172800, NS("b.gtld-servers.net.")},
		},
		[]ResourceRecord{
			{Name("a.gtld-servers.net."), TypeA, ClassIN, 172800, A(netip.MustParseAddr("192.5.6.30"))},
			{Name("a.gtld-servers.net."), TypeAAAA, ClassIN, 172800, AAAA(netip.MustParseAddr("2001:503:a83e::2:30"))},
			{Name("b.gtld-servers.net."), TypeA, ClassIN, 172800, A(netip.MustParseAddr("192.33.14.30"))},
			{Name("b.gtld-servers.net."), TypeAAAA, ClassIN, 172800, AAAA(netip.MustParseAddr("2001:503:231d::2:30"))},
		})

	// example.com.
	storeData("192.5.6.30:53", Question{Name("example.com."), QNameMinType, ClassIN},
		nil,
		[]ResourceRecord{
			{Name("example.com."), TypeNS, ClassIN, 172800, NS("a.iana-servers.net.")},
			{Name("example.com."), TypeNS, ClassIN, 172800, NS("b.iana-servers.net.")},
		},
		nil)

	// net.
	storeData("198.41.0.4:53", Question{Name("net."), QNameMinType, ClassIN},
		nil,
		[]ResourceRecord{
			{Name("net."), TypeNS, ClassIN, 172800, NS("a.gtld-servers.net.")},
			{Name("net."), TypeNS, ClassIN, 172800, NS("b.gtld-servers.net.")},
		},
		[]ResourceRecord{
			{Name("a.gtld-servers.net."), TypeA, ClassIN, 172800, A(netip.MustParseAddr("192.5.6.30"))},
			{Name("a.gtld-servers.net."), TypeAAAA, ClassIN, 172800, AAAA(netip.MustParseAddr("2001:503:a83e::2:30"))},
			{Name("b.gtld-servers.net."), TypeA, ClassIN, 172800, A(netip.MustParseAddr("192.33.14.30"))},
			{Name("b.gtld-servers.net."), TypeAAAA, ClassIN, 172800, AAAA(netip.MustParseAddr("2001:503:231d::2:30"))},
		})

	// iana-servers.net.
	storeData("192.5.6.30:53", Question{Name("iana-servers.net."), QNameMinType, ClassIN},
		nil,
		[]ResourceRecord{
			{Name("iana-servers.net."), TypeNS, ClassIN, 172800, NS("ns.icann.org.")},
			{Name("iana-servers.net."), TypeNS, ClassIN, 172800, NS("a.iana-servers.net.")},
			{Name("iana-servers.net."), TypeNS, ClassIN, 172800, NS("b.iana-servers.net.")},
		},
		[]ResourceRecord{
			{Name("a.iana-servers.net."), TypeA, ClassIN, 172800, A(netip.MustParseAddr("199.43.135.53"))},
			{Name("a.iana-servers.net."), TypeAAAA, ClassIN, 172800, AAAA(netip.MustParseAddr("2001:500:8f::53"))},
			{Name("b.iana-servers.net."), TypeA, ClassIN, 172800, A(netip.MustParseAddr("199.43.133.53"))},
			{Name("b.iana-servers.net."), TypeAAAA, ClassIN, 172800, AAAA(netip.MustParseAddr("2001:500:8d::53"))},
		})

	// example.com. A
	storeData("199.43.135.53:53", Question{Name("example.com."), TypeA, ClassIN},
		[]ResourceRecord{
			{Name("example.com."), TypeNS, ClassIN, 86400, A(netip.MustParseAddr("93.184.216.34"))},
		},
		nil,
		nil)

	// www.example.com.
	storeData("199.43.135.53:53", Question{Name("www.example.com."), QNameMinType, ClassIN},
		nil,
		[]ResourceRecord{
			{Name("example.com."), TypeSOA, ClassIN, 3600, SOA{"ns.icann.org.", "noc.dns.icann.org.", 2022091151, 7200, 3600, 1209600, 3600}},
		},
		nil)

	// www.example.com. A
	storeData("199.43.135.53:53", Question{Name("www.example.com."), TypeA, ClassIN},
		[]ResourceRecord{
			{Name("www.example.com."), TypeNS, ClassIN, 86400, A(netip.MustParseAddr("93.184.216.34"))},
		},
		nil,
		nil)

	// jp.
	storeData("198.41.0.4:53", Question{Name("jp."), QNameMinType, ClassIN},
		nil,
		[]ResourceRecord{
			{Name("jp."), TypeNS, ClassIN, 172800, NS("a.dns.jp.")},
			{Name("jp."), TypeNS, ClassIN, 172800, NS("b.dns.jp.")},
		},
		[]ResourceRecord{
			{Name("a.dns.jp."), TypeA, ClassIN, 172800, A(netip.MustParseAddr("203.119.1.1"))},
			{Name("a.dns.jp."), TypeAAAA, ClassIN, 172800, AAAA(netip.MustParseAddr("2001:dc4::1"))},
			{Name("b.dns.jp."), TypeA, ClassIN, 172800, A(netip.MustParseAddr("202.12.30.131"))},
			{Name("b.dns.jp."), TypeAAAA, ClassIN, 172800, AAAA(netip.MustParseAddr("2001:dc2::1"))},
		})

	// co.jp.
	storeData("203.119.1.1:53", Question{Name("co.jp."), QNameMinType, ClassIN},
		nil,
		[]ResourceRecord{
			{Name("jp."), TypeSOA, ClassIN, 900, SOA{"z.dns.jp.", "root.dns.jp.", 1668294003, 3600, 900, 1814400, 900}},
		},
		nil)

	// jprs.co.jp.
	storeData("203.119.1.1:53", Question{Name("jprs.co.jp."), QNameMinType, ClassIN},
		nil,
		[]ResourceRecord{
			{Name("jprs.co.jp."), TypeNS, ClassIN, 86400, NS("ns1.jprs.co.jp.")},
			{Name("jprs.co.jp."), TypeNS, ClassIN, 86400, NS("ns2.jprs.co.jp.")},
		},
		[]ResourceRecord{
			{Name("ns1.jprs.co.jp."), TypeA, ClassIN, 86400, A(netip.MustParseAddr("202.11.16.49"))},
			{Name("ns1.jprs.co.jp."), TypeAAAA, ClassIN, 86400, AAAA(netip.MustParseAddr("2001:df0:8::a153"))},
			{Name("ns2.jprs.co.jp."), TypeA, ClassIN, 86400, A(netip.MustParseAddr("202.11.16.59"))},
			{Name("ns2.jprs.co.jp."), TypeAAAA, ClassIN, 86400, AAAA(netip.MustParseAddr("2001:df0:8::a253"))},
		})

	// jprs.co.jp. A
	storeData("202.11.16.49:53", Question{Name("jprs.co.jp."), TypeA, ClassIN},
		[]ResourceRecord{
			{Name("jprs.co.jp."), TypeA, ClassIN, 300, A(netip.MustParseAddr("117.104.133.165"))},
		},
		[]ResourceRecord{
			{Name("jprs.co.jp."), TypeNS, ClassIN, 86400, NS("ns1.jprs.co.jp.")},
			{Name("jprs.co.jp."), TypeNS, ClassIN, 86400, NS("ns2.jprs.co.jp.")},
		},
		[]ResourceRecord{
			{Name("ns1.jprs.co.jp."), TypeA, ClassIN, 86400, A(netip.MustParseAddr("202.11.16.49"))},
			{Name("ns1.jprs.co.jp."), TypeAAAA, ClassIN, 86400, AAAA(netip.MustParseAddr("2001:df0:8::a153"))},
			{Name("ns2.jprs.co.jp."), TypeA, ClassIN, 86400, A(netip.MustParseAddr("202.11.16.59"))},
			{Name("ns2.jprs.co.jp."), TypeAAAA, ClassIN, 86400, AAAA(netip.MustParseAddr("2001:df0:8::a253"))},
		})

	mock := new(MockClient)
	mock.data = data
	return mock
}

func (c *MockClient) Do(network string, address string, question Question, rec bool, edns bool) (*Response, error) {
	key := MockClientDataKey{address, question}
	val, ok := c.data.Load(key)
	if ok {
		return val.(*Response), nil
	}
	return nil, fmt.Errorf("not found: %v", key)
}
