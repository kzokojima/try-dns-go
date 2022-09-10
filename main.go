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

func newQueryHeader() *header {
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

func (h header) String() string {
	opcodeTexts := []string{"QUERY", "IQUERY", "STATUS"}
	statusTexts := []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

	flags := make([]string, 0, 8)
	if h.qr() != 0 {
		flags = append(flags, "qr")
	}
	if h.aa() != 0 {
		flags = append(flags, "aa")
	}
	if h.tc() != 0 {
		flags = append(flags, "tc")
	}
	if h.rd() != 0 {
		flags = append(flags, "rd")
	}
	if h.ra() != 0 {
		flags = append(flags, "ra")
	}
	if h.z() != 0 {
		flags = append(flags, "z")
	}
	if h.ad() != 0 {
		flags = append(flags, "ad")
	}
	if h.cd() != 0 {
		flags = append(flags, "cd")
	}

	return fmt.Sprintf(";; ->>HEADER<<- opcode: %v, status: %v, id: %v\n"+
		";; flags: %v; QUERY: %v, ANSWER: %v, AUTHORITY: %v, ADDITIONAL: %v\n",
		opcodeTexts[h.opcode()],
		statusTexts[h.rcode()],
		h.id,
		strings.Join(flags, " "),
		h.qdCount,
		h.anCount,
		h.nsCount,
		h.arCount)
}

const (
	LABEL_LEN_MAX       = 63
	DOMAIN_NAME_LEN_MAX = 253
)

type name string

func (n name) String() string {
	return string(n)
}

func encodeName(in name) ([]byte, error) {
	if DOMAIN_NAME_LEN_MAX < len(in) {
		return nil, fmt.Errorf("%s length", in)
	}
	buf := new(bytes.Buffer)
	labels := strings.Split(string(in), ".")
	for _, label := range labels {
		len := len(label)
		if LABEL_LEN_MAX < len {
			return nil, fmt.Errorf("%s length", label)
		}
		buf.WriteByte(byte(len))
		buf.WriteString(label)
	}
	buf.WriteByte(byte(0))
	return buf.Bytes(), nil
}

func decodeName(data []byte, current int) (field, int, error) {
	buf := new(bytes.Buffer)
	i := current
	for {
		len := int(data[i])
		if len == 0 {
			i++
			break
		} else if len == 0xC0 {
			i = int(data[i+1])
			continue
		} else if len&0xC0 != 0 {
			return name(""), 0, fmt.Errorf("label length")
		}
		if buf.Len() != 0 {
			buf.WriteString(".")
		}
		i++
		buf.Write(data[i : i+len])
		i += len
	}
	buf.WriteString(".")
	next := i
	if i < current {
		next = current + 2
	}
	return name(buf.String()), next, nil
}

func decodeTexts(data []byte, current int, end int) []string {
	texts := make([]string, 0, 1)
	for current < end {
		txtlen := int(data[current])
		text := string(data[current+1 : current+1+txtlen])
		texts = append(texts, text)
		current += 1 + txtlen
	}
	return texts
}

type question struct {
	name  name
	type_ type_
	class class
}

var typeOf = map[string]type_{
	"A":     1,
	"NS":    2,
	"CNAME": 5,
	"MX":    15,
	"TXT":   16,
	"AAAA":  28,
	"OPT":   41,
}
var typeTextOf = map[type_]string{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	15: "MX",
	16: "TXT",
	28: "AAAA",
	41: "OPT",
}

var classOf = map[string]class{
	"IN": 1,
}

var classTextOf = map[class]string{
	1: "IN",
}

type field interface {
	String() string
}

type reader func(data []byte, current int) (field, int, error)

func readFields(data []byte, current int, readers ...reader) ([]field, int, error) {
	fields := make([]field, 0, len(readers))
	for _, reader := range readers {
		var (
			field field
			err   error
		)
		field, current, err = reader(data, current)
		if err != nil {
			return nil, 0, err
		}
		fields = append(fields, field)
	}
	return fields, current, nil
}

type type_ uint16

func (t type_) String() string {
	return typeTextOf[t]
}

func readType(data []byte, current int) (field, int, error) {
	type_ := type_(binary.BigEndian.Uint16(data[current:]))
	if _, ok := typeTextOf[type_]; ok {
		return type_, current + 2, nil
	}
	return type_, 0, fmt.Errorf("invalid type: %v", type_)
}

type class uint16

func (c class) String() string {
	return classTextOf[c]
}

func readClass(data []byte, current int) (field, int, error) {
	class := class(binary.BigEndian.Uint16(data[current:]))
	return class, current + 2, nil
}

type ttl uint16

func (t ttl) String() string {
	return fmt.Sprint(uint16(t))
}

func readTtl(data []byte, current int) (field, int, error) {
	ttl := ttl(binary.BigEndian.Uint32(data[current:]))
	return ttl, current + 4, nil
}

type rdlength uint16

func (l rdlength) String() string {
	return fmt.Sprint(uint16(l))
}

func readRdlength(data []byte, current int) (field, int, error) {
	rdlength := rdlength(binary.BigEndian.Uint16(data[current:]))
	return rdlength, current + 2, nil
}

func (q *question) bytes() ([]byte, error) {
	encoded, err := encodeName(q.name)
	if err != nil {
		return nil, err
	}

	len := len(encoded)
	bytes := make([]byte, len+4)
	copy(bytes, encoded)
	binary.BigEndian.PutUint16(bytes[len:], uint16(q.type_))
	binary.BigEndian.PutUint16(bytes[len+2:], uint16(q.class))
	return bytes, nil
}

func (q question) String() string {
	return fmt.Sprintf("%v %v %v", q.name, q.class, q.type_)
}

type resourceRecord struct {
	name  name
	type_ type_
	class class
	ttl   ttl
	val   string
}

func parseResourceRecord(data []byte, current int) (*resourceRecord, int, error) {
	var (
		val string
		err error
	)

	if data[current] != 0 {
		fields, current, err := readFields(data, current, decodeName, readType, readClass, readTtl, readRdlength)
		if err != nil {
			goto Error
		}
		name := fields[0].(name)
		type_ := fields[1].(type_)
		class := fields[2].(class)
		ttl := fields[3].(ttl)
		rdlength := fields[4].(rdlength)

		// rddata
		switch type_ := type_.String(); true {
		case (type_ == "A" && rdlength == 4) || (type_ == "AAAA" && rdlength == 16):
			ip, _ := netip.AddrFromSlice(data[current : current+int(rdlength)])
			val = ip.String()
		case type_ == "NS" || type_ == "CNAME":
			decoded, _, err := decodeName(data, current)
			if err != nil {
				goto Error
			}
			val = decoded.String()
		case type_ == "MX":
			preference := binary.BigEndian.Uint16(data[current:])
			exchange, _, err := decodeName(data, current+2)
			if err != nil {
				goto Error
			}
			val = fmt.Sprintf("%v %v", preference, exchange)
		case type_ == "TXT":
			texts := decodeTexts(data, current, current+int(rdlength))
			for i, v := range texts {
				texts[i] = fmt.Sprintf("%q", v)
			}
			val = strings.Join(texts, " ")
		default:
			val = fmt.Sprintf("unknown type: %v, rdlength: %v", type_, rdlength)
		}
		current += int(rdlength)

		return &resourceRecord{
			name,
			type_,
			class,
			ttl,
			val,
		}, current, nil
	} else { // OPT
		fields, _, err := readFields(data, current+1, readType, readClass, readTtl, readRdlength)
		if err != nil {
			return nil, 0, err
		}
		type_ := fields[0].(type_)
		class := fields[1].(class)
		ttl := fields[2].(ttl)

		return &resourceRecord{
			name(""),
			type_,
			class,
			ttl,
			"",
		}, current + OPT_RESOURCE_RECORD_HEADER_SIZE, nil
	}

Error:
	return nil, 0, err
}

func (rr resourceRecord) String() string {
	return fmt.Sprintf("%v %v %v %v %v", rr.name, rr.ttl, rr.class, rr.type_, rr.val)
}

type optResourceRecord struct {
	name  byte
	type_ uint16
	class uint16
	ttl   uint32
	rdlen uint16
}

const OPT_RESOURCE_RECORD_HEADER_SIZE = 11

func (opt *optResourceRecord) bytes() []byte {
	bytes := make([]byte, OPT_RESOURCE_RECORD_HEADER_SIZE)
	bytes[0] = opt.name
	binary.BigEndian.PutUint16(bytes[1:], opt.type_)
	binary.BigEndian.PutUint16(bytes[3:], opt.class)
	binary.BigEndian.PutUint32(bytes[5:], opt.ttl)
	binary.BigEndian.PutUint16(bytes[9:], opt.rdlen)
	return bytes
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
	fields, current, err := readFields(data, HEADER_SIZE, decodeName, readType, readClass)
	if err != nil {
		return nil, err
	}

	// Resource records
	records := make([]resourceRecord, header.resourceRecordCount())
	for i := 0; i < header.resourceRecordCount(); i++ {
		var record *resourceRecord
		record, current, err = parseResourceRecord(data, current)
		if err != nil {
			return nil, err
		}
		records[i] = *record
	}

	return &response{
		*header,
		question{fields[0].(name), fields[1].(type_), fields[2].(class)},
		records[:header.anCount],
		records[header.anCount : header.anCount+header.nsCount],
		records[header.anCount+header.nsCount : header.anCount+header.nsCount+header.arCount],
		current,
	}, nil
}

const UDP_SIZE = 1500

func makeReqMsg(n string, t string) ([]byte, error) {
	question := question{name(n), typeOf[t], classOf["IN"]}
	questionBytes, err := question.bytes()
	if err != nil {
		return nil, err
	}
	header := newQueryHeader()
	header.arCount = 1
	opt := optResourceRecord{
		type_: 41,
		class: UDP_SIZE, // UDP payload size
	}

	bytes := []byte{}
	bytes = append(bytes, header.bytes()...)
	bytes = append(bytes, questionBytes...)
	bytes = append(bytes, opt.bytes()...)

	return bytes, nil
}

func request(network string, address string, data []byte) ([]byte, error) {
	var buf [UDP_SIZE]byte
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
		fmt.Print(res.header)

		fmt.Println(";; QUESTION SECTION:")
		fmt.Printf(";%v\n\n", res.question)

		if 0 < len(res.answerResourceRecords) {
			fmt.Println(";; ANSWER SECTION:")
			for i := 0; i < len(res.answerResourceRecords); i++ {
				fmt.Println(res.answerResourceRecords[i])
			}
			fmt.Println()
		}

		if 0 < len(res.authorityResourceRecords) {
			fmt.Println(";; AUTHORITY SECTION:")
			for i := 0; i < len(res.authorityResourceRecords); i++ {
				fmt.Println(res.authorityResourceRecords[i])
			}
			fmt.Println()
		}

		arrs := make([]resourceRecord, 0, len(res.additionalResourceRecords))
		for i := 0; i < len(res.additionalResourceRecords); i++ {
			if res.additionalResourceRecords[i].type_.String() != "OPT" {
				arrs = append(arrs, res.additionalResourceRecords[i])
			}
		}
		if 0 < len(arrs) {
			fmt.Println(";; ADDITIONAL SECTION:")
			for i := 0; i < len(arrs); i++ {
				fmt.Println(arrs[i])
			}
			fmt.Println()
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
