package dns

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Header struct {
	ID      uint16
	Fields  uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

const HEADER_SIZE = 12

func parseHeader(data []byte) (*Header, error) {
	if len(data) < HEADER_SIZE {
		return nil, fmt.Errorf("header length")
	}
	return &Header{
		binary.BigEndian.Uint16(data),
		binary.BigEndian.Uint16(data[2:]),
		binary.BigEndian.Uint16(data[4:]),
		binary.BigEndian.Uint16(data[6:]),
		binary.BigEndian.Uint16(data[8:]),
		binary.BigEndian.Uint16(data[10:]),
	}, nil
}

func (h *Header) qr() uint16 {
	return h.Fields >> 15
}
func (h *Header) Opcode() uint16 {
	return (h.Fields & (0xf << 11) >> 11)
}

func (h *Header) aa() uint16 {
	return h.Fields & (1 << 10) >> 10
}

func (h *Header) tc() uint16 {
	return h.Fields & (1 << 9) >> 9
}

func (h *Header) rd() uint16 {
	return h.Fields & (1 << 8) >> 8
}

func (h *Header) ra() uint16 {
	return h.Fields & (1 << 7) >> 7
}

func (h *Header) z() uint16 {
	return h.Fields & (1 << 6) >> 6
}

func (h *Header) ad() uint16 {
	return h.Fields & (1 << 5) >> 5
}

func (h *Header) cd() uint16 {
	return h.Fields & (1 << 4) >> 4
}

func (h *Header) rcode() uint16 {
	return h.Fields & 0xf
}

func (h *Header) resourceRecordCount() int {
	return int(h.ANCount + h.NSCount + h.ARCount)
}

func (h *Header) Bytes() []byte {
	bytes := make([]byte, HEADER_SIZE)
	binary.BigEndian.PutUint16(bytes[:], h.ID)
	binary.BigEndian.PutUint16(bytes[2:], h.Fields)
	binary.BigEndian.PutUint16(bytes[4:], h.QDCount)
	binary.BigEndian.PutUint16(bytes[6:], h.ANCount)
	binary.BigEndian.PutUint16(bytes[8:], h.NSCount)
	binary.BigEndian.PutUint16(bytes[10:], h.ARCount)
	return bytes
}

func (h Header) String() string {
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
		opcodeTexts[h.Opcode()],
		statusTexts[h.rcode()],
		h.ID,
		strings.Join(flags, " "),
		h.QDCount,
		h.ANCount,
		h.NSCount,
		h.ARCount)
}

const (
	LABEL_LEN_MAX       = 63
	DOMAIN_NAME_LEN_MAX = 253
)

type Name string

func (n Name) String() string {
	return string(n)
}

func encodeName(in Name) ([]byte, error) {
	name := string(in)
	name = strings.TrimRight(name, ".")
	if DOMAIN_NAME_LEN_MAX < len(name) {
		return nil, fmt.Errorf("%s length", name)
	}
	buf := new(bytes.Buffer)
	labels := strings.Split(name, ".")
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
	return Name(buf.String()), next, nil
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

type Question struct {
	Name  Name
	Type  rrType
	Class class
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

const (
	TypeA  rrType = 1
	TypeMX rrType = 15
)

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

const (
	ClassIN class = 1
)

func (c class) String() string {
	return classTextOf[c]
}

func readClass(data []byte, current int) (field, int, error) {
	class := class(binary.BigEndian.Uint16(data[current:]))
	return class, current + 2, nil
}

type TTL uint32

func (t TTL) String() string {
	return fmt.Sprint(uint32(t))
}

func readTtl(data []byte, current int) (field, int, error) {
	ttl := TTL(binary.BigEndian.Uint32(data[current:]))
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

func (q *Question) Bytes() ([]byte, error) {
	encoded, err := encodeName(q.Name)
	if err != nil {
		return nil, err
	}

	len := len(encoded)
	bytes := make([]byte, len+4)
	copy(bytes, encoded)
	binary.BigEndian.PutUint16(bytes[len:], uint16(q.Type))
	binary.BigEndian.PutUint16(bytes[len+2:], uint16(q.Class))
	return bytes, nil
}

func (q Question) String() string {
	return fmt.Sprintf("%v %v %v", q.Name, q.Class, q.Type)
}

type RData interface {
	String() string
}

type RDataStr string

func (s RDataStr) String() string {
	return string(s)
}

type ResourceRecord struct {
	Name  Name
	Type  rrType
	Class class
	TTL   TTL
	RData RData
}

func parseResourceRecord(data []byte, current int) (*ResourceRecord, int, error) {
	if data[current] != 0 {
		var val string

		fields, current, err := readFields(data, current, decodeName, readType, readClass, readTtl, readRdlength)
		if err != nil {
			return nil, 0, err
		}
		name := fields[0].(Name)
		type_ := fields[1].(rrType)
		class := fields[2].(class)
		ttl := fields[3].(TTL)
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

		return &ResourceRecord{
			name,
			type_,
			class,
			ttl,
			RDataStr(val),
		}, current, nil
	} else { // OPT
		fields, _, err := readFields(data, current+1, readType, readClass, readTtl, readRdlength)
		if err != nil {
			return nil, 0, err
		}
		type_ := fields[0].(rrType)
		class := fields[1].(class)
		ttl := fields[2].(TTL)

		return &ResourceRecord{
			Name(""),
			type_,
			class,
			ttl,
			RDataStr(""),
		}, current + OPT_RESOURCE_RECORD_HEADER_SIZE, nil
	}
}

func (rr ResourceRecord) Bytes() ([]byte, error) {
	encoded, err := encodeName(rr.Name)
	if err != nil {
		return nil, err
	}
	l := len(encoded)
	bytes := make([]byte, l+10) // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
	copy(bytes, encoded)
	binary.BigEndian.PutUint16(bytes[l:], uint16(rr.Type))
	binary.BigEndian.PutUint16(bytes[l+2:], uint16(rr.Class))
	binary.BigEndian.PutUint32(bytes[l+4:], uint32(rr.TTL))
	switch rr.Type {
	case TypeA:
		addr, err := netip.ParseAddr(rr.RData.String())
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint16(bytes[l+8:], uint16(4))
		bytes = append(bytes, addr.AsSlice()...)
	case TypeMX:
		mx := rr.RData.(MX)
		name, err := encodeName(Name(mx.Exchange))
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint16(bytes[l+8:], uint16(2+uint16(len(name))))
		bytes = append(bytes, byte(0), byte(0))
		binary.BigEndian.PutUint16(bytes[l+10:], uint16(mx.Preference))
		bytes = append(bytes, name...)
	default:
		return nil, fmt.Errorf("type: %v", rr.Type)
	}
	return bytes, nil
}

func (rr ResourceRecord) String() string {
	return fmt.Sprintf("%v %v %v %v %v", rr.Name, rr.TTL, rr.Class, rr.Type, rr.RData.String())
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

type Response struct {
	Header                    Header
	Question                  Question
	AnswerResourceRecords     []ResourceRecord
	AuthorityResourceRecords  []ResourceRecord
	AdditionalResourceRecords []ResourceRecord
	MsgSize                   int
	QueryTime                 time.Duration
}

func MakeResponse(request Request, rrs []ResourceRecord) (*Response, error) {
	reqHeader := request.Header
	resHeader := Header{
		ID: reqHeader.ID,
		Fields: 1<<15 | // QR
			reqHeader.Opcode()<<11 | // OPCODE
			0, // RCODE
		QDCount: 1,
		ANCount: uint16(len(rrs)),
	}
	res := Response{
		resHeader,
		request.Question,
		rrs,
		nil,
		nil,
		0,
		0,
	}
	return &res, nil
}

func ParseResMsg(data []byte) (*Response, error) {
	msg, err := parseMessage(data)
	if err != nil {
		return nil, err
	}

	return &Response{
		msg.Header,
		msg.Question,
		msg.AnswerResourceRecords,
		msg.AuthorityResourceRecords,
		msg.AdditionalResourceRecords,
		msg.Size,
		0,
	}, nil
}

func (res *Response) Bytes() ([]byte, error) {
	questionBytes, err := res.Question.Bytes()
	if err != nil {
		return nil, err
	}
	bytes := []byte{}
	bytes = append(bytes, res.Header.Bytes()...)
	bytes = append(bytes, questionBytes...)
	for _, rr := range res.AnswerResourceRecords {
		rrBytes, err := rr.Bytes()
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, rrBytes...)
	}
	return bytes, nil
}

func MakeErrResMsg(request *Request) []byte {
	resHeader := Header{
		ID: request.Header.ID,
		Fields: 1<<15 | // QR
			request.Header.Opcode()<<11 | // OPCODE
			3, // RCODE(NXDOMAIN)
		QDCount: 1,
	}
	qbytes, err := request.Question.Bytes()
	if err != nil {
		return nil
	}
	res := append(resHeader.Bytes(), qbytes...)
	return res
}

const UDP_SIZE = 1500

type Request struct {
	Header                    Header
	Question                  Question
	AdditionalResourceRecords []ResourceRecord
	MsgSize                   int
}

func MakeReqMsg(n string, t string, rd bool) ([]byte, error) {
	question := Question{Name(n), typeOf[t], classOf["IN"]}
	questionBytes, err := question.Bytes()
	if err != nil {
		return nil, err
	}
	headerFields := map[bool]uint16{false: 0, true: 1 << 8}[rd]
	header := &Header{
		ID:      uint16(rand.Intn(0x10000)),
		Fields:  headerFields,
		QDCount: 1,
		ARCount: 1,
	}
	opt := optResourceRecord{
		type_: 41,
		class: UDP_SIZE, // UDP payload size
	}

	bytes := []byte{}
	bytes = append(bytes, header.Bytes()...)
	bytes = append(bytes, questionBytes...)
	bytes = append(bytes, opt.bytes()...)

	return bytes, nil
}

func ParseRequest(data []byte) (*Request, error) {
	msg, err := parseMessage(data)
	if err != nil {
		return nil, err
	}

	return &Request{
		msg.Header,
		msg.Question,
		msg.AdditionalResourceRecords,
		msg.Size,
	}, nil
}

type message struct {
	Header                    Header
	Question                  Question
	AnswerResourceRecords     []ResourceRecord
	AuthorityResourceRecords  []ResourceRecord
	AdditionalResourceRecords []ResourceRecord
	Size                      int
}

func parseMessage(msg []byte) (*message, error) {
	// Header section
	header, err := parseHeader(msg)
	if err != nil {
		return nil, err
	}

	// Question section
	fields, current, err := readFields(msg, HEADER_SIZE, decodeName, readType, readClass)
	if err != nil {
		return nil, err
	}

	// Resource records
	records := make([]ResourceRecord, header.resourceRecordCount())
	for i := 0; i < header.resourceRecordCount(); i++ {
		var record *ResourceRecord
		record, current, err = parseResourceRecord(msg, current)
		if err != nil {
			return nil, err
		}
		records[i] = *record
	}

	return &message{
		*header,
		Question{fields[0].(Name), fields[1].(rrType), fields[2].(class)},
		records[:header.ANCount],
		records[header.ANCount : header.ANCount+header.NSCount],
		records[header.ANCount+header.NSCount : header.ANCount+header.NSCount+header.ARCount],
		current,
	}, nil
}

type A = netip.Addr

type MX struct {
	Preference int
	Exchange   string
}

func (mx MX) String() string {
	return fmt.Sprint(mx.Preference, " ", mx.Exchange)
}
