package dns

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestMakeErrRes(t *testing.T) {
	req := Request{
		Header{},
		Question{"example.com.", TypeA, ClassIN},
		nil,
		0,
	}
	res := MakeErrResMsg(&req)
	if len(res) == 0 {
		t.Error("len(res) == 0")
	}
	_, err := ParseResMsg(res)
	if err != nil {
		t.Error(err)
	}
}

func TestParseRequest(t *testing.T) {
	reqMsg, err := MakeReqMsg("example.com", "A", true)
	if err != nil {
		t.Error(err)
	}
	request, err := ParseRequest(reqMsg)
	if err != nil {
		t.Error(err)
	}
	if request.Question.Name != "example.com." {
		t.Errorf("request.Question.Name: %v", request.Question.Name)
	}
}

func TestResponseBytes(t *testing.T) {
	{
		answers := []ResourceRecord{
			{Name("example.com."), TypeMX, ClassIN, 3600, MX{10, "mx1.example.com."}},
			{Name("example.com."), TypeMX, ClassIN, 3600, MX{20, "mx2.example.com."}},
		}
		authorities := []ResourceRecord{
			{Name("example.com."), TypeNS, ClassIN, 3600, NS("ns1.example.com.")},
			{Name("example.com."), TypeNS, ClassIN, 3600, NS("ns2.example.com.")},
		}
		additionals := []ResourceRecord{
			{Name("mx1.example.com."), TypeA, ClassIN, 600, netip.MustParseAddr("192.0.2.3")},
			{Name("mx2.example.com."), TypeA, ClassIN, 600, netip.MustParseAddr("192.0.2.4")},
			{Name("mx1.example.com."), TypeAAAA, ClassIN, 600, AAAA(netip.MustParseAddr("2001:db8::3"))},
			{Name("mx2.example.com."), TypeAAAA, ClassIN, 600, AAAA(netip.MustParseAddr("2001:db8::4"))},
		}
		res, err := MakeResponse(Header{}, Question{Name("example.com."), TypeMX, ClassIN}, answers, authorities, additionals)
		if err != nil {
			t.Error(err)
		}
		bytes, err := res.Bytes()
		if err != nil {
			t.Error(err)
		}
		if len(bytes) != 193 {
			t.Error(len(bytes))
		}
	}
	{
		answers := []ResourceRecord{
			{Name("www.example.com."), TypeCNAME, ClassIN, 3600, CNAME("example.com.")},
			{Name("example.com."), TypeA, ClassIN, 600, netip.MustParseAddr("192.0.2.1")},
			{Name("example.com."), TypeA, ClassIN, 600, netip.MustParseAddr("192.0.2.2")},
		}
		authorities := []ResourceRecord{
			{Name("example.com."), TypeNS, ClassIN, 3600, NS("ns1.example.com.")},
			{Name("example.com."), TypeNS, ClassIN, 3600, NS("ns2.example.com.")},
		}
		res, err := MakeResponse(Header{}, Question{Name("www.example.com."), TypeA, ClassIN}, answers, authorities, nil)
		if err != nil {
			t.Error(err)
		}
		bytes, err := res.Bytes()
		if err != nil {
			t.Error(err)
		}
		if len(bytes) != 115 {
			t.Error(len(bytes))
		}
	}
}

func TestEncodeTexts(t *testing.T) {
	texts := []string{
		"foo",
		"foobar",
	}
	bytes, err := encodeTexts(texts)
	if err != nil {
		t.Error(err)
	}
	if bytes[0] != 3 {
		t.Error(bytes[0])
	}
	if string(bytes[1:4]) != "foo" {
		t.Error(bytes[1:4])
	}
	if bytes[4] != 6 {
		t.Error(bytes[4])
	}
	if string(bytes[5:11]) != "foobar" {
		t.Error(bytes[5:11])
	}

	texts = []string{strings.Repeat("a", 255)}
	bytes, err = encodeTexts(texts)
	if err != nil {
		t.Error(err)
	}
	if bytes[0] != 255 {
		t.Error(bytes[0])
	}
	if string(bytes[1:256]) != strings.Repeat("a", 255) {
		t.Error(bytes[1:256])
	}
	texts = []string{strings.Repeat("a", 256)}
	_, err = encodeTexts(texts)
	if err == nil {
		t.Error("Validation error")
	}
}

func TestEncodeName(t *testing.T) {
	data := []struct {
		name     string
		msg      []byte
		expected []byte
	}{
		{"example.com.", nil, []byte("\x07example\x03com\x00")},
		{"example.com.", []byte("\x07example\x03com\x00"), []byte("\xC0\x00")},
		{"example.com.", []byte("\x03www\x07example\x03com\x00"), []byte("\xC0\x04")},
		{"mx1.example.com.", []byte("\x07example\x03com\x00"), []byte("\x03mx1\xC0\x00")},
		{"mx1.example.com.", []byte("\x07example\x03com\x00\x03mx1\xC0\x00"), []byte("\xC0\x0D")},
	}

	for _, v := range data {
		encoded, err := encodeName(v.name, v.msg)
		if err != nil {
			t.Error(v, err)
		}
		if !bytes.Equal(encoded, v.expected) {
			t.Error(v, encoded)
		}
	}
}
