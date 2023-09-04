package cmd

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

var clientUDP = &dns.Client{Net: "udp"}
var clientTCP = &dns.Client{Net: "tcp"}

func initDNS() {
	dur, _ := time.ParseDuration(fmt.Sprintf("%fs", opts.timeout))
	if dur < time.Microsecond {
		dur = time.Microsecond
	}
	log.Debug().Msgf("timeout configured: %s", dur)
	clientUDP.Timeout = dur
	clientTCP.Timeout = dur
}

func getNSFromSystem() (string, int, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", 0, fmt.Errorf("Error making client from resolv.conf: %w", err)
	}

	if !isElement(conf.Search, fmt.Sprintf("svc.%s", opts.zone)) {
		log.Warn().Msgf("Unabled to validate k8s zone (%s)", opts.zone)
	}

	port, err := strconv.Atoi(conf.Port)
	if err != nil {
		return "", 0, fmt.Errorf("Error converting port to int: %s", conf.Port)
	}

	return conf.Servers[0], port, nil
}

func queryPTR(ip net.IP) (*queryResult, error) {

	m := &dns.Msg{
		Question: make([]dns.Question, 1),
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
		},
	}

	revip := strings.Join(reverse(strings.Split(ip.String(), ".")), ".")
	ptr := fmt.Sprintf("%s.in-addr.arpa.", revip)
	fqdn := dns.Fqdn(ptr)

	log.Trace().Msgf("querying PTR %s, %s", ip.String(), fqdn)
	m.Question[0] = dns.Question{
		Name:   fqdn,
		Qtype:  dns.TypePTR,
		Qclass: dns.ClassINET,
	}
	res, err := multiProtoQueryRecord(m)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}

	return &queryResult{
		answers:    res.answers,
		additional: res.additional,
		raw:        res.raw,
		ip:         &ip,
		rtt:        res.rtt,
	}, nil
}

func queryA(aname string) (*queryResult, error) {
	m := &dns.Msg{
		Question: make([]dns.Question, 1),
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
		},
	}

	log.Trace().Msgf("querying A record for %s", aname)
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(aname),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	return multiProtoQueryRecord(m)
}

func querySRV(aname string) (*queryResult, error) {
	m := &dns.Msg{
		Question: make([]dns.Question, 1),
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
		},
	}

	log.Trace().Msgf("querying SRV record for %s", aname)
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(aname),
		Qtype:  dns.TypeSRV,
		Qclass: dns.ClassINET,
	}
	return multiProtoQueryRecord(m)
}

func queryTXT(txt string) (*queryResult, error) {
	m := &dns.Msg{
		Question: make([]dns.Question, 1),
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
		},
	}

	log.Trace().Msgf("querying TXT record for %s", txt)
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(txt),
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	}
	return multiProtoQueryRecord(m)
}

func multiProtoQueryRecord(m *dns.Msg) (*queryResult, error) {
	switch opts.proto {
	case "auto":
		return autoProtoQueryRecord(m)
	case "udp":
		return queryRecord(clientUDP, m)
	case "tcp":
		return queryRecord(clientTCP, m)
	default:
		return nil, fmt.Errorf("Unknown protocol %s", opts.proto)
	}
}

func autoProtoQueryRecord(m *dns.Msg) (*queryResult, error) {
	res, err := queryRecord(clientUDP, m)
	if err != nil {
		return nil, err
	}

	if res == nil {
		return nil, nil
	}

	if !res.raw.Truncated {
		return res, nil
	}

	log.Debug().Msgf("Got truncated response for %s, retrying with TCP", m.Question[0].Name)

	return queryRecord(clientTCP, m)
}

func queryRecord(client *dns.Client, m *dns.Msg) (*queryResult, error) {
	r, rtt, err := client.Exchange(m, fmt.Sprintf("%s:%d", opts.nameserver, opts.nameport))
	if err != nil {
		var dnsError *net.OpError
		if errors.As(err, &dnsError) && strings.Contains(err.Error(), "timeout") {
			return nil, nil
		}
		return nil, err
	}

	if r != nil && len(r.Answer) > 0 {
		return &queryResult{
			answers:    r.Answer,
			additional: r.Extra,
			raw:        r,
			rtt:        &rtt,
		}, nil
	}
	return nil, nil
}

func parseSRVAnswer(ans string) (string, string, int, error) {
	parts := strings.Split(ans, "\t")
	if len(parts) != 5 {
		return "", "", 0, fmt.Errorf("Error parsing SRV: %s", ans)
	}
	parts4 := strings.Split(parts[4], " ")
	if len(parts4) != 4 {
		return "", "", 0, fmt.Errorf("Error parsing SRV: %s", parts4)
	}
	port, err := strconv.Atoi(parts4[2])
	if err != nil {
		return "", "", 0, err
	}
	name, ns := parseDNSPodName(parts4[3])
	return name, ns, port, nil
}

func parseAAnswer(ans string) (string, string, net.IP, error) {
	parts := strings.Split(ans, "\t")
	if len(parts) != 5 {
		return "", "", nil, fmt.Errorf("Error parsing A: %s", ans)
	}
	name, ns := parseDNSPodName(parts[0])
	ip := net.ParseIP(parts[4])
	if ip == nil {
		return "", "", nil, fmt.Errorf("Error parsing IP address: %s", parts[4])
	}
	return name, ns, ip, nil
}

func parseDNSPodName(fqdn string) (string, string) {
	parts := strings.Split(fqdn, ".")

	if len(parts) == 7 {
		return parts[1], parts[2]
	}

	return parts[0], parts[1]
}
