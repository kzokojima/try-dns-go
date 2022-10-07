package dns

import (
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
