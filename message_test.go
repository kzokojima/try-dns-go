package dns

import (
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
