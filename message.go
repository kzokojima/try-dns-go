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

type ResourceRecord struct {
	Name  name
	Type  rrType
	Class class
	Ttl   ttl
	Val   string
}

func parseResourceRecord(data []byte, current int) (*ResourceRecord, int, error) {
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

		return &ResourceRecord{
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

		return &ResourceRecord{
			name(""),
			type_,
			class,
			ttl,
			"",
		}, current + OPT_RESOURCE_RECORD_HEADER_SIZE, nil
	}
}

func (rr ResourceRecord) String() string {
	return fmt.Sprintf("%v %v %v %v %v", rr.Name, rr.Ttl, rr.Class, rr.Type, rr.Val)
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
	Header                    header
	Question                  question
	AnswerResourceRecords     []ResourceRecord
	AuthorityResourceRecords  []ResourceRecord
	AdditionalResourceRecords []ResourceRecord
	MsgSize                   int
	QueryTime                 time.Duration
}

func ParseResMsg(data []byte) (*Response, error) {
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
	records := make([]ResourceRecord, header.resourceRecordCount())
	for i := 0; i < header.resourceRecordCount(); i++ {
		var record *ResourceRecord
		record, current, err = parseResourceRecord(data, current)
		if err != nil {
			return nil, err
		}
		records[i] = *record
	}

	return &Response{
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

func MakeReqMsg(n string, t string, rd bool) ([]byte, error) {
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
