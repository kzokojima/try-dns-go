package dns

import (
	"encoding/binary"
	"net"
)

type Client struct{}

func (c *Client) Do(network string, address string, name string, type_ string, rec bool) ([]byte, error) {
	reqMsg, err := MakeReqMsg(name, type_, rec)
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
