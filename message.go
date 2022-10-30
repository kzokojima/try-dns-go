package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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

const headerSize = 12

func parseHeader(data []byte) (*Header, error) {
	if len(data) < headerSize {
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
	bytes := make([]byte, headerSize)
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
	labelLenMax      = 63
	domainNameLenMax = 253
)

type Name string

func (n Name) MarshalBinary(msg []byte) (data []byte, err error) {
	return encodeName(string(n), msg)
}

func (n Name) String() string {
	return string(n)
}

func encodeName(name string, msg []byte) ([]byte, error) {
	if name == "" || name == "." {
		return []byte{0}, nil
	}

	name = strings.TrimRight(name, ".")
	if domainNameLenMax < len(name) {
		return nil, fmt.Errorf("%s length", name)
	}

	if len(msg) != 0 {
		// message compression

		// search for FQDN
		encoded, err := encodeName(name, nil)
		if err != nil {
			return nil, err
		}
		if i := bytes.Index(msg, encoded); i != -1 {
			// simple match
			return []byte{0xC0 | byte(i>>8), byte(i & 0xFF)}, nil
		}

		fields := strings.SplitN(name, ".", 2)
		if len(fields) == 2 {
			lavel0, err := encodeName(fields[0], nil)
			if err != nil {
				return nil, err
			}
			lavel0 = lavel0[:len(lavel0)-1] // trim null character

			// search for lavel0 + lavel1 pointer
			lavel1, err := encodeName(fields[1], nil)
			if err != nil {
				return nil, err
			}
			if i := bytes.Index(msg, lavel1); i != -1 {
				search := append(lavel0, 0xC0|byte(i>>8), byte(i&0xFF))
				if i := bytes.Index(msg, search); i != -1 {
					return []byte{0xC0 | byte(i>>8), byte(i & 0xFF)}, nil
				}
			}

			lavel1, err = encodeName(fields[1], msg)
			if err != nil {
				return nil, err
			}
			return append(lavel0, lavel1...), nil
		}
	}

	buf := new(bytes.Buffer)
	labels := strings.Split(name, ".")
	for _, label := range labels {
		len := len(label)
		if labelLenMax < len {
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

func encodeTexts(texts []string) ([]byte, error) {
	bytes := make([]byte, 0)
	for _, text := range texts {
		l := len(text)
		if 255 < l {
			return nil, fmt.Errorf("invalid length")
		}
		bytes = append(bytes, byte(len(text)))
		bytes = append(bytes, text...)
	}
	return bytes, nil
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
	Type  Type
	Class class
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

func readType(data []byte, current int) (field, int, error) {
	type_ := Type(binary.BigEndian.Uint16(data[current:]))
	if _, ok := typeTexts[type_]; ok {
		return type_, current + 2, nil
	}
	return type_, 0, fmt.Errorf("invalid type: %v", uint16(type_))
}

type class uint16
type Class = class

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
	encoded, err := encodeName(q.Name.String(), nil)
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
	MarshalBinary(msg []byte) (data []byte, err error)
	String() string
}

type RDataStr string

func (s RDataStr) MarshalBinary(msg []byte) (data []byte, err error) {
	// TODO
	return
}

func (s RDataStr) String() string {
	return string(s)
}

type ResourceRecord struct {
	Name  Name
	Type  Type
	Class class
	TTL   TTL
	RData RData
}

func parseResourceRecord(data []byte, current int) (*ResourceRecord, int, error) {
	var val string

	fields, current, err := readFields(data, current, decodeName, readType, readClass, readTtl, readRdlength)
	if err != nil {
		return nil, 0, fmt.Errorf("%v, fields: %v", err, fields)
	}
	name := fields[0].(Name)
	type_ := fields[1].(Type)
	class := fields[2].(class)
	ttl := fields[3].(TTL)
	rdlength := fields[4].(rdlength)
	var rdata RData

	// rddata
	switch type_ {
	case TypeA:
		ip, _ := netip.AddrFromSlice(data[current : current+int(rdlength)])
		rdata = A(ip)
	case TypeAAAA:
		ip, _ := netip.AddrFromSlice(data[current : current+int(rdlength)])
		rdata = AAAA(ip)
	case TypeNS, TypeCNAME, TypePTR:
		decoded, _, err := decodeName(data, current)
		if err != nil {
			return nil, 0, err
		}
		val = decoded.String()
		rdata = Name(val)
	case TypeMX:
		preference := binary.BigEndian.Uint16(data[current:])
		exchange, _, err := decodeName(data, current+2)
		if err != nil {
			return nil, 0, err
		}
		rdata = MX{preference, exchange.String()}
	case TypeSOA:
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
		rdata = SOA{mname.String(), rname.String(), serial, refresh, retry, expire, minimum}
	case TypeTXT:
		texts := decodeTexts(data, current, current+int(rdlength))
		for i, v := range texts {
			texts[i] = fmt.Sprintf("%q", v)
		}
		rdata = newTxt(texts)
	case TypeOPT:
		rdata = RDataStr("")
	case TypeDS:
		keyTag := binary.BigEndian.Uint16(data[current:])
		algo := data[current+2]
		digestType := data[current+3]
		digest := data[current+4 : current+int(rdlength)]
		rdata = DS{keyTag, algo, digestType, digest}
	case TypeRRSIG:
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
		rdata = RRSIG{typeCovered.String(), algo, labels, originalTtl,
			signatureExpiration.Format(LAYOUT), signatureInception.Format(LAYOUT),
			keyTag, signerName, base64.StdEncoding.EncodeToString(signature)}
	case TypeNSEC:
		decoded, next, err := decodeName(data, current)
		if err != nil {
			return nil, 0, err
		}
		nextDomainName := decoded.String()
		windowBlock := data[next]
		bitmapLen := int(data[next+1])
		bitmap := data[next+2 : next+2+bitmapLen]
		var texts []string
		var types []int
		for v := range typeTexts {
			types = append(types, int(v))
		}
		sort.Ints(types)
		if windowBlock == 0 {
			for _, v := range types {
				if v/8 < bitmapLen && bitmap[v/8]>>(7-v%8)&1 == 1 {
					texts = append(texts, typeTexts[Type(uint16(v))])
				}
			}
		}
		rdata = NSEC{nextDomainName, strings.Join(texts, " ")}
	case TypeDNSKEY:
		flags := binary.BigEndian.Uint16(data[current:])
		proto := data[current+2]
		if proto != 3 {
			return nil, 0, fmt.Errorf("DNSKEY proto: %v", proto)
		}
		algo := data[current+3]
		key := data[current+4 : current+int(rdlength)]
		rdata = DNSKEY{flags, proto, algo, base64.StdEncoding.EncodeToString(key)}
	default:
		rdata = RDataStr(fmt.Sprintf("unknown type: %v, rdlength: %v", type_, rdlength))
	}
	current += int(rdlength)

	return &ResourceRecord{
		name,
		type_,
		class,
		ttl,
		rdata,
	}, current, nil
}

func (rr ResourceRecord) Bytes(msg []byte) ([]byte, error) {
	encoded, err := encodeName(rr.Name.String(), msg)
	if err != nil {
		return nil, err
	}
	l := len(encoded)
	bytes := make([]byte, l+10) // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
	copy(bytes, encoded)
	binary.BigEndian.PutUint16(bytes[l:], uint16(rr.Type))
	binary.BigEndian.PutUint16(bytes[l+2:], uint16(rr.Class))
	binary.BigEndian.PutUint32(bytes[l+4:], uint32(rr.TTL))
	var rdata []byte
	switch rr.Type {
	case TypeA, TypeNS, TypeCNAME, TypeMX, TypeTXT, TypeAAAA:
		rdata, err = rr.RData.MarshalBinary(msg)
		if err != nil {
			return nil, err
		}
	case TypeOPT:
	default:
		return nil, fmt.Errorf("type: %v", rr.Type)
	}
	binary.BigEndian.PutUint16(bytes[l+8:], uint16(len(rdata)))
	bytes = append(bytes, rdata...)
	return bytes, nil
}

func (rr ResourceRecord) String() string {
	return fmt.Sprintf("%v %v %v %v %v", rr.Name, rr.TTL, rr.Class, rr.Type, rr.RData.String())
}

type Response struct {
	Header                    Header
	Question                  Question
	AnswerResourceRecords     []ResourceRecord
	AuthorityResourceRecords  []ResourceRecord
	AdditionalResourceRecords []ResourceRecord
	MsgSize                   int
	QueryTime                 time.Duration
	RawMsg                    []byte
}

func MakeResponse(reqHeader Header, question Question,
	answers []ResourceRecord, authorities []ResourceRecord, additionals []ResourceRecord) (*Response, error) {
	resHeader := Header{
		ID: reqHeader.ID,
		Fields: 1<<15 | // QR
			reqHeader.Opcode()<<11 | // OPCODE
			0, // RCODE
		QDCount: 1,
		ANCount: uint16(len(answers)),
		NSCount: uint16(len(authorities)),
		ARCount: uint16(len(additionals)),
	}
	res := Response{
		resHeader,
		question,
		answers,
		authorities,
		additionals,
		0,
		0,
		nil,
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
		data,
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
		rrBytes, err := rr.Bytes(bytes)
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, rrBytes...)
	}
	for _, rr := range res.AuthorityResourceRecords {
		rrBytes, err := rr.Bytes(bytes)
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, rrBytes...)
	}
	for _, rr := range res.AdditionalResourceRecords {
		rrBytes, err := rr.Bytes(bytes)
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

const udpSize = 1500

type Request struct {
	Header                    Header
	Question                  Question
	AdditionalResourceRecords []ResourceRecord
	MsgSize                   int
}

func MakeReqMsg(n string, t string, rd bool, edns bool) ([]byte, error) {
	typeText, err := typeFromString(t)
	if err != nil {
		return nil, err
	}
	question := Question{Name(n), typeText, classOf["IN"]}
	questionBytes, err := question.Bytes()
	if err != nil {
		return nil, err
	}
	headerFields := map[bool]uint16{false: 0, true: 1 << 8}[rd]

	var arcount uint16
	var arbytes []byte
	if edns {
		arcount = 1
		opt := ResourceRecord{
			Type:  TypeOPT,
			Class: udpSize, // UDP payload size
		}
		bytes, err := opt.Bytes(nil)
		if err != nil {
			return nil, err
		}
		arbytes = append(arbytes, bytes...)
	}

	rnd := make([]byte, 2)
	_, err = rand.Read(rnd)
	if err != nil {
		return nil, err
	}
	header := &Header{
		ID:      binary.BigEndian.Uint16(rnd),
		Fields:  headerFields,
		QDCount: 1,
		ARCount: arcount,
	}

	bytes := []byte{}
	bytes = append(bytes, header.Bytes()...)
	bytes = append(bytes, questionBytes...)
	bytes = append(bytes, arbytes...)

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
	fields, current, err := readFields(msg, headerSize, decodeName, readType, readClass)
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
		Question{fields[0].(Name), fields[1].(Type), fields[2].(class)},
		records[:header.ANCount],
		records[header.ANCount : header.ANCount+header.NSCount],
		records[header.ANCount+header.NSCount : header.ANCount+header.NSCount+header.ARCount],
		current,
	}, nil
}
