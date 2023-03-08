package main

import (
	"fmt"
	"testing"
	"try/dns"
)

func TestResolve(t *testing.T) {
	dns.Log.SetLogLevel(dns.LogLevelDebug)
	dns.SetUpResolver("../../root_files/named.root", "../../root_files/root-anchors.xml")

	req := dns.Request{
		Header: dns.Header{
			ID:      0,
			Fields:  0,
			QDCount: 1,
			ANCount: 0,
			NSCount: 0,
			ARCount: 0,
		},
		Question:                  dns.Question{Name: dns.Name("example.com."), Type: dns.TypeA, Class: dns.ClassIN},
		AdditionalResourceRecords: nil,
		MsgSize:                   0,
	}
	res, err := resolver(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.AnswerResourceRecords) == 0 {
		fmt.Print(res)
		t.Fatal("no answers")
	}
}
