package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

type header struct {
	id      uint16
	fields  uint16
	qdCount uint16
	anCount uint16
	nsCount uint16
	arCount uint16
}

const HEADER_SIZE = 12

func makeQueryHeader() *header {
	h := &header{}
	h.id = uint16(rand.Intn(0x10000))
	h.fields = 1 << 8 // RD
	h.qdCount = 1
	return h
}

func parseHeader(data []byte) (*header, error) {
	if len(data) < HEADER_SIZE {
		return nil, fmt.Errorf("header length")
	}
	return &header{
		binary.BigEndian.Uint16(data),
		binary.BigEndian.Uint16(data[2:]),
		binary.BigEndian.Uint16(data[4:]),
		binary.BigEndian.Uint16(data[6:]),
		binary.BigEndian.Uint16(data[8:]),
		binary.BigEndian.Uint16(data[10:]),
	}, nil
}

func (h *header) qr() uint16 {
	return h.fields >> 15
}
func (h *header) opcode() uint16 {
	return (h.fields & (0xf << 11) >> 11)
}

func (h *header) aa() uint16 {
	return h.fields & (1 << 10) >> 10
}

func (h *header) tc() uint16 {
	return h.fields & (1 << 9) >> 9
}

func (h *header) rd() uint16 {
	return h.fields & (1 << 8) >> 8
}

func (h *header) ra() uint16 {
	return h.fields & (1 << 7) >> 7
}

func (h *header) z() uint16 {
	return h.fields & (1 << 6) >> 6
}

func (h *header) ad() uint16 {
	return h.fields & (1 << 5) >> 5
}

func (h *header) cd() uint16 {
	return h.fields & (1 << 4) >> 4
}

func (h *header) rcode() uint16 {
	return h.fields & 0xf
}

func (h *header) resourceRecordCount() int {
	return int(h.anCount + h.nsCount + h.arCount)
}

func (h *header) bytes() []byte {
	bytes := make([]byte, HEADER_SIZE)
	binary.BigEndian.PutUint16(bytes[:], h.id)
	binary.BigEndian.PutUint16(bytes[2:], h.fields)
	binary.BigEndian.PutUint16(bytes[4:], h.qdCount)
	binary.BigEndian.PutUint16(bytes[6:], h.anCount)
	binary.BigEndian.PutUint16(bytes[8:], h.nsCount)
	binary.BigEndian.PutUint16(bytes[10:], h.arCount)
	return bytes
}

func (h *header) string() string {
	return fmt.Sprintf(`;ID:      %v
;QR:      %v
;OPCODE:  %v
;AA:      %v
;TC:      %v
;RD:      %v
;RA:      %v
;Z:       %v
;AD:      %v
;CD:      %v
;RCODE:   %v
;QDCOUNT: %v
;ANCOUNT: %v
;NSCOUNT: %v
;ARCOUNT: %v
`,
		h.id,
		h.qr(),
		h.opcode(),
		h.aa(),
		h.tc(),
		h.rd(),
		h.ra(),
		h.z(),
		h.ad(),
		h.cd(),
		h.rcode(),
		h.qdCount,
		h.anCount,
		h.nsCount,
		h.arCount)
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

type question struct {
	name  string
	type_ string
	class string
}

var typeOf = map[string]uint16{
	"A":     1,
	"NS":    2,
	"CNAME": 5,
	"MX":    15,
	"TXT":   16,
	"AAAA":  28,
}
var typeNameOf = map[uint16]string{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	15: "MX",
	16: "TXT",
	28: "AAAA",
}

var classOf = map[string]uint16{
	"IN": 1,
}

var classNameOf = map[uint16]string{
	1: "IN",
}

func parseQuestionSection(data []byte, offset int) (*question, int, error) {
	var (
		ok        bool
		type_     string
		type_val  uint16
		class     string
		class_val uint16
	)

	// name
	name, offset, err := decodeName(data, offset)
	if err != nil {
		goto Error
	}

	// type
	type_val = binary.BigEndian.Uint16(data[offset:])
	type_, ok = typeNameOf[type_val]
	if !ok {
		err = fmt.Errorf("invalid type: %v", type_val)
		goto Error
	}

	// class
	class_val = binary.BigEndian.Uint16(data[offset+2:])
	class, ok = classNameOf[class_val]
	if !ok {
		err = fmt.Errorf("invalid class: %v", class_val)
		goto Error
	}

	return &question{name, type_, class}, offset + 4, nil

Error:
	return nil, 0, err
}

func (q *question) bytes() ([]byte, error) {
	encoded, err := encodeName(q.name)
	if err != nil {
		return nil, err
	}
	type_val, ok := typeOf[q.type_]
	if !ok {
		return nil, fmt.Errorf("invalid type: %s", q.type_)
	}
	class_val, ok := classOf[q.class]
	if !ok {
		return nil, fmt.Errorf("invalid class: %s", q.class)
	}

	len := len(encoded)
	bytes := make([]byte, len+4)
	copy(bytes, encoded)
	binary.BigEndian.PutUint16(bytes[len:], type_val)
	binary.BigEndian.PutUint16(bytes[len+2:], class_val)
	return bytes, nil
}

func (q *question) string() string {
	return fmt.Sprintf("%v %v %v", q.name, q.class, q.type_)
}

type resourceRecord struct {
	name  string
	type_ string
	class string
	ttl   uint32
	val   string
}

func parseResourceRecord(data []byte, offset int) (*resourceRecord, int, error) {
	var (
		ttl      uint32
		rdlength uint16
		val      string
	)

	question, offset, err := parseQuestionSection(data, offset)
	if err != nil {
		goto Error
	}

	// ttl
	ttl = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// rdlength
	rdlength = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// rddata
	if (question.type_ == "A" && rdlength == 4) || (question.type_ == "AAAA" && rdlength == 16) {
		ip, _ := netip.AddrFromSlice(data[offset : offset+int(rdlength)])
		val = ip.String()
	} else if question.type_ == "NS" || question.type_ == "CNAME" {
		name, _, err := decodeName(data, offset)
		if err != nil {
			goto Error
		}
		val = name
	} else if question.type_ == "MX" {
		preference := binary.BigEndian.Uint16(data[offset:])
		exchange, _, err := decodeName(data, offset+2)
		if err != nil {
			goto Error
		}
		val = fmt.Sprintf("%v %v", preference, exchange)
	} else if question.type_ == "TXT" {
		txtlen := int(data[offset])
		txt := string(data[offset+1 : offset+1+txtlen])
		val = fmt.Sprintf("%q", txt)
	} else {
		val = fmt.Sprintf("unknown type: %v, rdlength: %v", question.type_, rdlength)
	}
	offset += int(rdlength)

	return &resourceRecord{question.name, question.type_, question.class, ttl, val}, offset, nil

Error:
	return nil, 0, err
}

func (rr *resourceRecord) string() string {
	return fmt.Sprintf("%v %v %v %v %v", rr.name, rr.ttl, rr.class, rr.type_, rr.val)
}

type response struct {
	header                    header
	question                  question
	answerResourceRecords     []resourceRecord
	authorityResourceRecords  []resourceRecord
	additionalResourceRecords []resourceRecord
	msgSize                   int
}

func parseResMsg(data []byte) (*response, error) {
	// Header section
	header, err := parseHeader(data)
	if err != nil {
		return nil, err
	}

	if header.rcode() != 0 {
		return nil, fmt.Errorf("RCODE: %v", header.rcode())
	}

	// Question section
	question, offset, err := parseQuestionSection(data, HEADER_SIZE)
	if err != nil {
		return nil, err
	}

	// Resource records
	records := make([]resourceRecord, header.resourceRecordCount())
	for i := 0; i < header.resourceRecordCount(); i++ {
		var record *resourceRecord
		record, offset, err = parseResourceRecord(data, offset)
		if err != nil {
			return nil, err
		}
		records[i] = *record
	}

	return &response{
		*header,
		*question,
		records[:header.anCount],
		records[header.anCount : header.anCount+header.nsCount],
		records[header.anCount+header.nsCount : header.anCount+header.nsCount+header.arCount],
		offset,
	}, nil
}

func makeReqMsg(name string, type_ string) ([]byte, error) {
	question := question{name, type_, "IN"}
	questionBytes, err := question.bytes()
	if err != nil {
		return nil, err
	}

	return append(makeQueryHeader().bytes(), questionBytes...), nil
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

type opts struct {
	server string
	port   string
	name   string
	type_  string
	short  bool
}

func getOpts(args []string) (*opts, error) {
	var opts = &opts{
		port:  "53",
		type_: "A",
	}
	for i := 0; i < len(args); i++ {
		switch {
		case strings.HasPrefix(args[i], "@"):
			opts.server = args[i][1:]
		case args[i] == "-p":
			i++
			opts.port = args[i]
		case strings.HasPrefix(args[i], "-p"):
			opts.port = args[i][2:]
		case strings.HasPrefix(args[i], "+"):
			switch args[i] {
			case "+short":
				opts.short = true
			default:
				return nil, fmt.Errorf("invalid arg: %v", args[i])
			}
		case len(opts.name) == 0:
			opts.name = strings.ToLower(args[i])
		default:
			opts.type_ = strings.ToUpper(args[i])
		}
	}
	if len(opts.server) == 0 || len(opts.port) == 0 || len(opts.name) == 0 || len(opts.type_) == 0 {
		return nil, fmt.Errorf("args not found")
	}
	return opts, nil
}

func print(res *response, opts *opts) {
	if opts.short {
		for i := 0; i < len(res.answerResourceRecords); i++ {
			fmt.Println(res.answerResourceRecords[i].val)
		}
	} else {
		fmt.Print(res.header.string())

		fmt.Println(";; QUESTION SECTION:")
		fmt.Printf(";%v\n", res.question.string())

		if 0 < len(res.answerResourceRecords) {
			fmt.Println(";; ANSWER SECTION:")
			for i := 0; i < len(res.answerResourceRecords); i++ {
				fmt.Println(res.answerResourceRecords[i].string())
			}
		}

		if 0 < len(res.authorityResourceRecords) {
			fmt.Println(";; AUTHORITY SECTION:")
			for i := 0; i < len(res.authorityResourceRecords); i++ {
				fmt.Println(res.authorityResourceRecords[i].string())
			}
		}

		if 0 < len(res.additionalResourceRecords) {
			fmt.Println(";; ADDITIONAL SECTION:")
			for i := 0; i < len(res.additionalResourceRecords); i++ {
				fmt.Println(res.additionalResourceRecords[i].string())
			}
		}
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func main() {
	rand.Seed(time.Now().UnixNano())

	opts, err := getOpts(os.Args[1:])
	if err != nil {
		die(err)
	}
	reqMsg, err := makeReqMsg(opts.name, opts.type_)
	if err != nil {
		die(err)
	}
	resMsg, err := request("udp", opts.server+":"+opts.port, reqMsg)
	if err != nil {
		die(err)
	}
	res, err := parseResMsg(resMsg)
	if err != nil {
		die(err)
	}
	print(res, opts)
}
