package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
	"unsafe"
)

type opts struct {
	server string
	port   string
	name   string
	type_  string
}

type dnsMessageHeader struct {
	Id      uint16
	Fields  uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

var typeOf = map[string]byte{
	"A":     1,
	"NS":    2,
	"CNAME": 5,
	"MX":    15,
	"TXT":   16,
	"AAAA":  28,
}
var typeNameOf = map[byte]string{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	15: "MX",
	16: "TXT",
	28: "AAAA",
}

var classNameOf = map[byte]string{
	1: "IN",
}

func encodeName(in string) ([]byte, error) {
	if 253 < len(in) {
		return nil, fmt.Errorf("%s length", in)
	}
	buf := new(bytes.Buffer)
	labels := strings.Split(in, ".")
	for _, label := range labels {
		len := len(label)
		if 63 < len {
			return nil, fmt.Errorf("%s length", label)
		}
		buf.WriteByte(byte(len))
		buf.WriteString(label)
	}
	buf.WriteByte(byte(0))
	return buf.Bytes(), nil
}

func decodeName(data []byte, offset int) (string, int, error) {
	buf := new(bytes.Buffer)
	i := offset
	for {
		len := int(data[i])
		if len == 0 {
			i++
			break
		} else if len == 0xC0 {
			i = int(data[i+1])
			continue
		} else if len&0xC0 != 0 {
			return "", 0, fmt.Errorf("label length")
		}
		if buf.Len() != 0 {
			buf.WriteString(".")
		}
		i++
		buf.Write(data[i : i+len])
		i += len
	}
	buf.WriteString(".")
	new_offset := i
	if i < offset {
		new_offset = offset + 2
	}
	return buf.String(), new_offset, nil
}

func makeResolveRequest(name string, type_ string) ([]byte, error) {
	encoded, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	type_val, ok := typeOf[type_]
	if !ok {
		return nil, fmt.Errorf("invalid type: %s", type_)
	}
	const CLASS byte = 1

	header := dnsMessageHeader{}
	header.Id = uint16(rand.Intn(0x10000))
	header.Fields = 1 << 8
	header.QdCount = 1
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, header)
	buf.Write(encoded)
	buf.Write([]byte{0, type_val, 0, CLASS})
	return buf.Bytes(), nil
}

func request(network string, address string, data []byte) ([]byte, error) {
	var buf [512]byte
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}
	len, err := conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	return buf[:len], nil
}

func getOpts() (*opts, error) {
	var opts = &opts{
		port:  "53",
		type_: "A",
	}
	for i := 1; i < len(os.Args); i++ {
		if strings.Index(os.Args[i], "@") == 0 {
			opts.server = strings.TrimLeft(os.Args[i], "@")
		} else if strings.Index(os.Args[i], "-p") == 0 {
			i++
			opts.port = os.Args[i]
		} else if len(opts.name) == 0 {
			opts.name = strings.ToLower(os.Args[i])
		} else {
			opts.type_ = strings.ToUpper(os.Args[i])
		}
	}
	if len(opts.server) == 0 || len(opts.port) == 0 || len(opts.name) == 0 || len(opts.type_) == 0 {
		return nil, fmt.Errorf("args not found")
	}
	return opts, nil
}

func parseQuestionSection(data []byte, offset int) (string, string, string, int, error) {
	var (
		ok        bool
		type_     string
		type_val  uint16
		class     string
		class_val uint16
	)
	reader := bytes.NewReader(data)

	// name
	name, offset, err := decodeName(data, offset)
	if err != nil {
		goto Error
	}
	reader.Seek(int64(offset), io.SeekStart)

	// type
	err = binary.Read(reader, binary.BigEndian, &type_val)
	if err != nil {
		goto Error
	}
	type_, ok = typeNameOf[byte(type_val)]
	if !ok {
		err = fmt.Errorf("invalid type: %v", type_val)
		goto Error
	}

	// class
	err = binary.Read(reader, binary.BigEndian, &class_val)
	if err != nil {
		goto Error
	}
	class, ok = classNameOf[byte(class_val)]
	if !ok {
		err = fmt.Errorf("invalid class: %v", class_val)
		goto Error
	}

	return name, type_, class, offset + 4, nil

Error:
	return "", "", "", 0, err
}

func parseResourceRecord(data []byte, offset int) (string, string, string, uint32, string, int, error) {
	var (
		ttl      uint32
		rdlength uint16
		rdbuf    [512]byte
		val      string
	)
	reader := bytes.NewReader(data)

	name, type_, class, offset, err := parseQuestionSection(data, offset)
	if err != nil {
		goto Error
	}
	reader.Seek(int64(offset), io.SeekStart)

	// ttl
	err = binary.Read(reader, binary.BigEndian, &ttl)
	if err != nil {
		goto Error
	}
	offset += int(unsafe.Sizeof(ttl))

	// rdlength
	err = binary.Read(reader, binary.BigEndian, &rdlength)
	if err != nil {
		goto Error
	}
	offset += int(unsafe.Sizeof(rdlength))

	// rddata
	if (type_ == "A" && rdlength == 4) || (type_ == "AAAA" && rdlength == 16) {
		ip, _ := netip.AddrFromSlice(data[offset+0 : offset+int(rdlength)])
		val = ip.String()
	} else if type_ == "NS" {
		nsdname, _, err := decodeName(data, offset)
		if err != nil {
			goto Error
		}
		val = fmt.Sprintf("%v", nsdname)
	} else if type_ == "CNAME" {
		cname, _, err := decodeName(data, offset)
		if err != nil {
			goto Error
		}
		val = fmt.Sprintf("%v", cname)
	} else if type_ == "MX" {
		var preference uint16
		err = binary.Read(reader, binary.BigEndian, &preference)
		if err != nil {
			goto Error
		}
		exchange, _, err := decodeName(data, offset+2)
		if err != nil {
			goto Error
		}
		val = fmt.Sprintf("%v %v", preference, exchange)
	} else if type_ == "TXT" {
		txtlen, err := reader.ReadByte()
		if err != nil {
			goto Error
		}
		rddata := rdbuf[:txtlen]
		err = binary.Read(reader, binary.BigEndian, rddata)
		if err != nil {
			goto Error
		}
		val = fmt.Sprintf("%q", rddata)
	} else {
		val = fmt.Sprintf("unknown type: %v, rdlength: %v", type_, rdlength)
	}
	offset += int(rdlength)

	return name, type_, class, ttl, val, offset, nil

Error:
	return "", "", "", 0, "", 0, err
}

func printResourceRecords(data []byte, offset int, count uint16) (int, error) {
	var (
		name  string
		type_ string
		class string
		ttl   uint32
		val   string
		err   error
		i     uint16
	)
	for i = 0; i < count; i++ {
		name, type_, class, ttl, val, offset, err = parseResourceRecord(data, offset)
		if err != nil {
			return 0, err
		}
		fmt.Printf("%v %v %v %v %v\n", name, ttl, class, type_, val)
	}
	return offset, nil
}

func print(data []byte) error {
	var (
		name   string
		type_  string
		class  string
		offset int
		err    error
	)

	// Header section
	reader := bytes.NewReader(data)
	header := dnsMessageHeader{}
	err = binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return err
	}
	rcode := header.Fields & 0xf
	fmt.Printf(";ID:      %v\n", header.Id)
	fmt.Printf(";QR:      %v\n", header.Fields>>15)
	fmt.Printf(";OPCODE:  %v\n", (header.Fields & (0xf << 11) >> 11))
	fmt.Printf(";AA:      %v\n", header.Fields&(1<<10)>>10)
	fmt.Printf(";TC:      %v\n", header.Fields&(1<<9)>>9)
	fmt.Printf(";RD:      %v\n", header.Fields&(1<<8)>>8)
	fmt.Printf(";RA:      %v\n", header.Fields&(1<<7)>>7)
	fmt.Printf(";Z:       %v\n", header.Fields&(1<<6)>>6)
	fmt.Printf(";AD:      %v\n", header.Fields&(1<<5)>>5)
	fmt.Printf(";CD:      %v\n", header.Fields&(1<<4)>>4)
	fmt.Printf(";RCODE:   %v\n", rcode)
	fmt.Printf(";QDCOUNT: %v\n", header.QdCount)
	fmt.Printf(";ANCOUNT: %v\n", header.AnCount)
	fmt.Printf(";NSCOUNT: %v\n", header.NsCount)
	fmt.Printf(";ARCOUNT: %v\n", header.ArCount)

	// Question section
	fmt.Println(";; QUESTION SECTION:")
	name, type_, class, offset, err = parseQuestionSection(data, 12)
	if err != nil {
		return err
	}
	fmt.Printf(";%v %v %v\n", name, class, type_)

	if rcode != 0 {
		fmt.Printf("; ERROR: %v\n", rcode)
		return nil
	}

	if 0 < header.AnCount {
		// Answer section
		fmt.Println(";; ANSWER SECTION:")
		offset, err = printResourceRecords(data, offset, header.AnCount)
		if err != nil {
			return err
		}
	}

	if 0 < header.NsCount {
		// Authority section
		fmt.Println(";; AUTHORITY SECTION:")
		offset, err = printResourceRecords(data, offset, header.NsCount)
		if err != nil {
			return err
		}
	}

	if 0 < header.ArCount {
		// Additional section
		fmt.Println(";; ADDITIONAL SECTION:")
		offset, err = printResourceRecords(data, offset, header.ArCount)
		if err != nil {
			return err
		}
	}

	// fmt.Printf(";; MSG SIZE  rcvd: %v\n", offset)

	return nil
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func main() {
	rand.Seed(time.Now().UnixNano())

	opts, err := getOpts()
	if err != nil {
		die(err)
	}
	req, err := makeResolveRequest(opts.name, opts.type_)
	if err != nil {
		die(err)
	}
	res, err := request("udp", opts.server+":"+opts.port, req)
	if err != nil {
		die(err)
	}
	err = print(res)
	if err != nil {
		die(err)
	}
}
