package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sort"
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
	next := -1
	buf := new(bytes.Buffer)
	i := current
	for {
		len := int(data[i])
		if len == 0 {
			i++
			break
		} else if len&0xC0 == 0xC0 {
			if next == -1 {
				next = i + 2
			}
			i = (len & ^0xC0 << 8) + int(data[i+1])
			continue
		}
		if buf.Len() != 0 {
			buf.WriteString(".")
		}
		i++
		buf.Write(data[i : i+len])
		i += len
	}
	buf.WriteString(".")
	if next == -1 {
		next = i
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
	type_ rrType
	class class
}

var typeOf = map[string]rrType{
	"A":      1,
	"NS":     2,
	"CNAME":  5,
	"SOA":    6,
	"PTR":    12,
	"MX":     15,
	"TXT":    16,
	"AAAA":   28,
	"OPT":    41,
	"DS":     43,
	"RRSIG":  46,
	"NSEC":   47,
	"DNSKEY": 48,
}
var typeTextOf = map[rrType]string{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	6:  "SOA",
	12: "PTR",
	15: "MX",
	16: "TXT",
	28: "AAAA",
	41: "OPT",
	43: "DS",
	46: "RRSIG",
	47: "NSEC",
	48: "DNSKEY",
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

type rrType uint16

func (t rrType) String() string {
	return typeTextOf[t]
}

func readType(data []byte, current int) (field, int, error) {
	type_ := rrType(binary.BigEndian.Uint16(data[current:]))
	if _, ok := typeTextOf[type_]; ok {
		return type_, current + 2, nil
	}
	return type_, 0, fmt.Errorf("invalid type: %v", uint16(type_))
}

type class uint16

func (c class) String() string {
	return classTextOf[c]
}

func readClass(data []byte, current int) (field, int, error) {
	class := class(binary.BigEndian.Uint16(data[current:]))
	return class, current + 2, nil
}

type ttl uint32

func (t ttl) String() string {
	return fmt.Sprint(uint32(t))
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
	type_ rrType
	class class
	ttl   ttl
	val   string
}

func parseResourceRecord(data []byte, current int) (*resourceRecord, int, error) {
	if data[current] != 0 {
		var val string

		fields, current, err := readFields(data, current, decodeName, readType, readClass, readTtl, readRdlength)
		if err != nil {
			return nil, 0, err
		}
		name := fields[0].(name)
		type_ := fields[1].(rrType)
		class := fields[2].(class)
		ttl := fields[3].(ttl)
		rdlength := fields[4].(rdlength)

		// rddata
		switch type_ := type_.String(); true {
		case (type_ == "A" && rdlength == 4) || (type_ == "AAAA" && rdlength == 16):
			ip, _ := netip.AddrFromSlice(data[current : current+int(rdlength)])
			val = ip.String()
		case type_ == "NS" || type_ == "CNAME" || type_ == "PTR":
			decoded, _, err := decodeName(data, current)
			if err != nil {
				return nil, 0, err
			}
			val = decoded.String()
		case type_ == "MX":
			preference := binary.BigEndian.Uint16(data[current:])
			exchange, _, err := decodeName(data, current+2)
			if err != nil {
				return nil, 0, err
			}
			val = fmt.Sprintf("%v %v", preference, exchange)
		case type_ == "SOA":
			mname, next, err := decodeName(data, current)
			if err != nil {
				return nil, 0, err
			}
			rname, next, err := decodeName(data, next)
			if err != nil {
				return nil, 0, err
			}
			serial := binary.BigEndian.Uint32(data[next:])
			refresh := binary.BigEndian.Uint32(data[next+4:])
			retry := binary.BigEndian.Uint32(data[next+8:])
			expire := binary.BigEndian.Uint32(data[next+12:])
			minimum := binary.BigEndian.Uint32(data[next+16:])
			val = fmt.Sprintf("%v %v %v %v %v %v %v", mname, rname, serial, refresh, retry, expire, minimum)
		case type_ == "TXT":
			texts := decodeTexts(data, current, current+int(rdlength))
			for i, v := range texts {
				texts[i] = fmt.Sprintf("%q", v)
			}
			val = strings.Join(texts, " ")
		case type_ == "DS":
			keyTag := binary.BigEndian.Uint16(data[current:])
			algo := data[current+2]
			digestType := data[current+3]
			digest := data[current+4 : current+int(rdlength)]
			val = fmt.Sprintf("%v %v %v %X", keyTag, algo, digestType, digest)
		case type_ == "RRSIG":
			typeCovered, _, _ := readType(data, current)
			algo := data[current+2]
			labels := data[current+3]
			originalTtl := binary.BigEndian.Uint32(data[current+4:])
			signatureExpiration := time.Unix(int64(binary.BigEndian.Uint32(data[current+8:])), 0).UTC()
			signatureInception := time.Unix(int64(binary.BigEndian.Uint32(data[current+12:])), 0).UTC()
			keyTag := binary.BigEndian.Uint16(data[current+16:])
			decoded, next, err := decodeName(data, current+18)
			if err != nil {
				return nil, 0, err
			}
			signerName := decoded.String()
			signature := data[next : current+int(rdlength)]
			const LAYOUT = "20060102150405"
			val = fmt.Sprintf("%v %v %v %v %v %v %v %v %v",
				typeCovered.String(), algo, labels, originalTtl,
				signatureExpiration.Format(LAYOUT), signatureInception.Format(LAYOUT),
				keyTag, signerName, base64.StdEncoding.EncodeToString(signature))
		case type_ == "NSEC":
			decoded, next, err := decodeName(data, current)
			if err != nil {
				return nil, 0, err
			}
			nextDomainName := decoded.String()
			windowBlock := data[next]
			bitmapLen := int(data[next+1])
			bitmap := data[next+2 : next+2+bitmapLen]
			var typeTexts []string
			var types []int
			for _, v := range typeOf {
				types = append(types, int(v))
			}
			sort.Ints(types)
			if windowBlock == 0 {
				for _, v := range types {
					if v/8 < bitmapLen && bitmap[v/8]>>(7-v%8)&1 == 1 {
						typeTexts = append(typeTexts, typeTextOf[rrType(uint16(v))])
					}
				}
			}
			val = fmt.Sprintf("%v %v", nextDomainName, strings.Join(typeTexts, " "))
		case type_ == "DNSKEY":
			flags := binary.BigEndian.Uint16(data[current:])
			proto := data[current+2]
			if proto != 3 {
				return nil, 0, fmt.Errorf("DNSKEY proto: %v", proto)
			}
			algo := data[current+3]
			key := data[current+4 : current+int(rdlength)]
			val = fmt.Sprintf("%v %v %v %v", flags, proto, algo, base64.StdEncoding.EncodeToString(key))
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
		type_ := fields[0].(rrType)
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
	query_time                time.Duration
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
		question{fields[0].(name), fields[1].(rrType), fields[2].(class)},
		records[:header.anCount],
		records[header.anCount : header.anCount+header.nsCount],
		records[header.anCount+header.nsCount : header.anCount+header.nsCount+header.arCount],
		current,
		0,
	}, nil
}

const UDP_SIZE = 1500

func makeReqMsg(n string, t string, rd bool) ([]byte, error) {
	question := question{name(n), typeOf[t], classOf["IN"]}
	questionBytes, err := question.bytes()
	if err != nil {
		return nil, err
	}
	headerFields := map[bool]uint16{false: 0, true: 1 << 8}[rd]
	header := &header{
		id:      uint16(rand.Intn(0x10000)),
		fields:  headerFields,
		qdCount: 1,
		arCount: 1,
	}
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

func arpaName(ipaddr string) (string, error) {
	parts := strings.Split(ipaddr, ".")
	if len(parts) == 4 { // IPv4
		parts[0], parts[1], parts[2], parts[3] = parts[3], parts[2], parts[1], parts[0]
		return strings.Join(parts, ".") + ".in-addr.arpa", nil
	} else { // IPv6
		addr, err := netip.ParseAddr(ipaddr)
		if err != nil {
			return "", err
		}
		expanded := addr.StringExpanded()
		parts := make([]byte, 64)
		for i, j := 0, len(expanded)-1; i < len(parts); i, j = i+1, j-1 {
			if expanded[j] == ':' {
				j--
			}
			parts[i] = expanded[j]
			i++
			parts[i] = '.'
		}
		return string(parts) + "ip6.arpa", nil
	}
}

type opts struct {
	server  string
	port    string
	reverse bool
	name    string
	type_   string
	short   bool
	tcp     bool
	rec     bool
}

func getOpts(args []string) (*opts, error) {
	var opts = &opts{
		port:  "53",
		type_: "A",
		rec:   true,
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
		case args[i] == "-x":
			opts.reverse = true
			opts.type_ = "PTR"
		case strings.HasPrefix(args[i], "+"):
			switch args[i] {
			case "+short":
				opts.short = true
			case "+tcp":
				opts.tcp = true
			case "+norec":
				opts.rec = false
			default:
				return nil, fmt.Errorf("invalid arg: %v", args[i])
			}
		case len(opts.name) == 0:
			opts.name = strings.ToLower(args[i])
		default:
			opts.type_ = strings.ToUpper(args[i])
		}
	}
	if len(opts.port) == 0 || len(opts.name) == 0 || len(opts.type_) == 0 {
		return nil, fmt.Errorf("args not found")
	}
	return opts, nil
}

func defaultNameServer() (string, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\n")
		if line[0] == '#' {
			continue
		}
		elems := strings.Split(line, " ")
		if len(elems) == 2 && elems[0] == "nameserver" {
			return elems[1], nil
		}
	}
}

func print(res *response, opts *opts) {
	if opts.short {
		for i := 0; i < len(res.answerResourceRecords); i++ {
			fmt.Println(res.answerResourceRecords[i].val)
		}
	} else {
		var opt *resourceRecord
		additionals := make([]resourceRecord, 0, len(res.additionalResourceRecords))
		for i := 0; i < len(res.additionalResourceRecords); i++ {
			if res.additionalResourceRecords[i].type_.String() == "OPT" {
				opt = &res.additionalResourceRecords[i]
			} else {
				additionals = append(additionals, res.additionalResourceRecords[i])
			}
		}

		fmt.Print(res.header)
		fmt.Println()

		flags := ""
		if ((opt.ttl >> 15) & 1) == 1 {
			flags = " do"
		}
		fmt.Println(";; OPT PSEUDOSECTION:")
		fmt.Printf("; EDNS: version: %v, flags:%v; udp: %v\n", (opt.ttl>>16)&0xf, flags, int(opt.class))

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

		if 0 < len(additionals) {
			fmt.Println(";; ADDITIONAL SECTION:")
			for i := 0; i < len(additionals); i++ {
				fmt.Println(additionals[i])
			}
			fmt.Println()
		}
		fmt.Printf(";; Query time: %v\n", res.query_time)
		fmt.Printf(";; SERVER: %v#%v(%v)\n", opts.server, opts.port, opts.server)
		fmt.Printf(";; WHEN: %v\n", time.Now().Format(time.RFC3339))
		fmt.Printf(";; MSG SIZE  rcvd: %v\n", res.msgSize)
		fmt.Println()
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
	if opts.server == "" {
		server, err := defaultNameServer()
		if err != nil {
			die(err)
		}
		opts.server = server
	}
	if opts.reverse {
		opts.name, err = arpaName(opts.name)
		if err != nil {
			die(err)
		}
	}
	reqMsg, err := makeReqMsg(opts.name, opts.type_, opts.rec)
	if err != nil {
		die(err)
	}
	network := "udp"
	if opts.tcp {
		network = "tcp"
		reqMsg = append([]byte{0, 0}, reqMsg...)
		binary.BigEndian.PutUint16(reqMsg, uint16(len(reqMsg)-2))
	}
	time_sent := time.Now()
	resMsg, err := request(network, opts.server+":"+opts.port, reqMsg)
	if err != nil {
		die(err)
	}
	query_time := time.Since(time_sent)
	if opts.tcp {
		resMsg = resMsg[2:]
	}
	res, err := parseResMsg(resMsg)
	if err != nil {
		die(err)
	}
	res.query_time = query_time
	print(res, opts)
}
