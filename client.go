package dns

import (
	"encoding/binary"
	"fmt"
	"net"
)

type Client struct {
	Limit int
	count int
}

func (c *Client) Do(network string, address string, name string, type_ string, rec bool, edns bool) ([]byte, error) {
	c.count++
	if 1 <= c.Limit && c.Limit < c.count {
		return nil, fmt.Errorf("exceed count")
	}
	reqMsg, err := MakeReqMsg(name, type_, rec, edns)
	if err != nil {
		return nil, err
	}
	if network == "tcp" {
		reqMsg = append([]byte{0, 0}, reqMsg...)
		binary.BigEndian.PutUint16(reqMsg, uint16(len(reqMsg)-2))
	}

	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(reqMsg)
	if err != nil {
		return nil, err
	}
	var buf [UDP_SIZE]byte
	len, err := conn.Read(buf[:])
	if err != nil {
		return nil, err
	}

	return buf[:len], nil
}
