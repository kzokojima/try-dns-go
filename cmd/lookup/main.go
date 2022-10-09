package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"try/dns"
)

func request(network string, address string, data []byte) ([]byte, error) {
	var buf [dns.UDP_SIZE]byte
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
	raw     bool
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
			case "+raw":
				opts.raw = true
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

func print(res *dns.Response, opts *opts) {
	if opts.short {
		for i := 0; i < len(res.AnswerResourceRecords); i++ {
			fmt.Println(res.AnswerResourceRecords[i].RData)
		}
	} else {
		var opt *dns.ResourceRecord
		additionals := make([]dns.ResourceRecord, 0, len(res.AdditionalResourceRecords))
		for i := 0; i < len(res.AdditionalResourceRecords); i++ {
			if res.AdditionalResourceRecords[i].Type.String() == "OPT" {
				opt = &res.AdditionalResourceRecords[i]
			} else {
				additionals = append(additionals, res.AdditionalResourceRecords[i])
			}
		}

		fmt.Print(res.Header)
		fmt.Println()

		if opt != nil {
			flags := ""
			if ((opt.TTL >> 15) & 1) == 1 {
				flags = " do"
			}
			fmt.Println(";; OPT PSEUDOSECTION:")
			fmt.Printf("; EDNS: version: %v, flags:%v; udp: %v\n", (opt.TTL>>16)&0xf, flags, int(opt.Class))
		}

		fmt.Println(";; QUESTION SECTION:")
		fmt.Printf(";%v\n\n", res.Question)

		if 0 < len(res.AnswerResourceRecords) {
			fmt.Println(";; ANSWER SECTION:")
			for i := 0; i < len(res.AnswerResourceRecords); i++ {
				fmt.Println(res.AnswerResourceRecords[i])
			}
			fmt.Println()
		}

		if 0 < len(res.AuthorityResourceRecords) {
			fmt.Println(";; AUTHORITY SECTION:")
			for i := 0; i < len(res.AuthorityResourceRecords); i++ {
				fmt.Println(res.AuthorityResourceRecords[i])
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
		fmt.Printf(";; Query time: %v\n", res.QueryTime)
		fmt.Printf(";; SERVER: %v#%v(%v)\n", opts.server, opts.port, opts.server)
		fmt.Printf(";; WHEN: %v\n", time.Now().Format(time.RFC3339))
		fmt.Printf(";; MSG SIZE  rcvd: %v\n", res.MsgSize)
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
	reqMsg, err := dns.MakeReqMsg(opts.name, opts.type_, opts.rec)
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
	if opts.raw {
		os.Stdout.Write(resMsg)
	} else {
		query_time := time.Since(time_sent)
		if opts.tcp {
			resMsg = resMsg[2:]
		}
		res, err := dns.ParseResMsg(resMsg)
		if err != nil {
			die(err)
		}
		res.QueryTime = query_time
		print(res, opts)
	}
}
