package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"try/dns"
)

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
		name:  ".",
		type_: "NS",
		rec:   true,
	}
	name_flg := false
	type_flg := false
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
			type_flg = true
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
		case !name_flg:
			opts.name = strings.ToLower(args[i])
			name_flg = true
			if !type_flg {
				opts.type_ = "A"
			}
		case !type_flg:
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

func printBytes(b []byte) {
	var buf [16]byte
	reader := bytes.NewReader(b)
	for {
		n, err := reader.Read(buf[:])
		if err != nil {
			return
		}
		fmt.Printf("%x\n", buf[:n])
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func main() {
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
	network := "udp"
	if opts.tcp {
		network = "tcp"
	}
	client := dns.Client{}
	res, err := client.Do(network, opts.server+":"+opts.port, opts.name, opts.type_, opts.rec, true)
	if err != nil {
		if res != nil {
			printBytes(res.RawMsg)
		}
		die(err)
	}
	if opts.raw {
		os.Stdout.Write(res.RawMsg)
	} else {
		print(res, opts)
	}
}
