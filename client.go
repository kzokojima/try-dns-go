package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type Client interface {
	Do(network string, address string, question Question, rec bool, edns bool) (*Response, error)
}

type BasicClient struct {
	Limit int
	count int
}

func (c *BasicClient) Do(network string, address string, question Question, rec bool, edns bool) (*Response, error) {
	c.count++
	if 1 <= c.Limit && c.Limit < c.count {
		return nil, fmt.Errorf("exceed count")
	}
	reqMsg, err := MakeReqMsg(question, rec, edns)
	if err != nil {
		return nil, err
	}
	if network == "tcp" {
		reqMsg = append([]byte{0, 0}, reqMsg...)
		binary.BigEndian.PutUint16(reqMsg, uint16(len(reqMsg)-2))
	}

	timeSent := time.Now()
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(reqMsg)
	if err != nil {
		return nil, err
	}
	var buf [udpSize]byte
	len, err := conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	queryTime := time.Since(timeSent)
	offset := 0
	if network == "tcp" {
		offset = 2
	}
	res, err := ParseResMsg(buf[offset:len])
	if err != nil {
		res = &Response{RawMsg: buf[offset:len]}
		return res, err
	}
	res.QueryTime = queryTime
	return res, nil
}
