package dnsclient

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"

	"github.com/jpts/coredns-enum/pkg/types"
	"github.com/jpts/coredns-enum/pkg/util"
)

type DNSClient struct {
	UDPClient *dns.Client
	TCPClient *dns.Client
	CliOpts   *types.CliOpts
}

func InitDNS(opts *types.CliOpts) *DNSClient {
	dur, _ := time.ParseDuration(fmt.Sprintf("%fs", opts.Timeout))
	if dur < time.Microsecond {
		dur = time.Microsecond
	}
	log.Debug().Msgf("timeout configured: %s", dur)

	clientUDP := &dns.Client{
		Net:     "udp",
		Timeout: dur,
	}
	clientTCP := &dns.Client{
		Net:     "tcp",
		Timeout: dur,
	}

	return &DNSClient{
		UDPClient: clientUDP,
		TCPClient: clientTCP,
		CliOpts:   opts,
	}
}

func (d *DNSClient) GetNSFromSystem() (string, int, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", 0, fmt.Errorf("Error making client from resolv.conf: %w", err)
	}

	if !util.IsElement(conf.Search, fmt.Sprintf("svc.%s", d.CliOpts.Zone)) {
		log.Warn().Msgf("Unabled to validate k8s zone (%s)", d.CliOpts.Zone)
	}

	port, err := strconv.Atoi(conf.Port)
	if err != nil {
		return "", 0, fmt.Errorf("Error converting port to int: %s", conf.Port)
	}

	return conf.Servers[0], port, nil
}

func (d *DNSClient) QueryPTR(ip net.IP) (*types.QueryResult, error) {

	m := &dns.Msg{
		Question: make([]dns.Question, 1),
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
		},
	}

	revip := strings.Join(util.Reverse(strings.Split(ip.String(), ".")), ".")
	ptr := fmt.Sprintf("%s.in-addr.arpa.", revip)
	fqdn := dns.Fqdn(ptr)

	log.Trace().Msgf("querying PTR %s, %s", ip.String(), fqdn)
	m.Question[0] = dns.Question{
		Name:   fqdn,
		Qtype:  dns.TypePTR,
		Qclass: dns.ClassINET,
	}
	res, err := d.MultiProtoQueryRecord(m)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}

	return &types.QueryResult{
		Answers:    res.Answers,
		Additional: res.Additional,
		Raw:        res.Raw,
		IP:         &ip,
		RTT:        res.RTT,
	}, nil
}

func (d *DNSClient) QueryA(aname string) (*types.QueryResult, error) {
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
	return d.MultiProtoQueryRecord(m)
}

func (d *DNSClient) QuerySRV(aname string) (*types.QueryResult, error) {
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
	return d.MultiProtoQueryRecord(m)
}

func (d *DNSClient) QueryTXT(txt string) (*types.QueryResult, error) {
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
	return d.MultiProtoQueryRecord(m)
}

func (d *DNSClient) MultiProtoQueryRecord(m *dns.Msg) (*types.QueryResult, error) {
	switch d.CliOpts.Proto {
	case "auto":
		return d.AutoProtoQueryRecord(m)
	case "udp":
		return d.queryRecord(d.UDPClient, m)
	case "tcp":
		return d.queryRecord(d.TCPClient, m)
	default:
		return nil, fmt.Errorf("Unknown protocol %s", d.CliOpts.Proto)
	}
}

func (d *DNSClient) AutoProtoQueryRecord(m *dns.Msg) (*types.QueryResult, error) {
	res, err := d.queryRecord(d.UDPClient, m)
	if err != nil {
		return nil, err
	}

	if res == nil {
		return nil, nil
	}

	if !res.Raw.Truncated {
		return res, nil
	}

	log.Debug().Msgf("Got truncated response for %s, retrying with TCP", m.Question[0].Name)

	return d.queryRecord(d.TCPClient, m)
}

func (d *DNSClient) queryRecord(client *dns.Client, m *dns.Msg) (*types.QueryResult, error) {
	r, rtt, err := client.Exchange(m, fmt.Sprintf("%s:%d", d.CliOpts.Nameserver, d.CliOpts.Nameport))
	if err != nil {
		var dnsError *net.OpError
		if errors.As(err, &dnsError) && strings.Contains(err.Error(), "timeout") {
			return nil, nil
		}
		return nil, err
	}

	if r != nil && len(r.Answer) > 0 {
		return &types.QueryResult{
			Answers:    r.Answer,
			Additional: r.Extra,
			Raw:        r,
			RTT:        &rtt,
		}, nil
	}
	return nil, nil
}

func ParseSRVAnswer(ans string) (string, string, int, error) {
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
	name, ns := ParseDNSPodName(parts4[3])
	return name, ns, port, nil
}

func ParseAAnswer(ans string) (string, string, net.IP, error) {
	parts := strings.Split(ans, "\t")
	if len(parts) != 5 {
		return "", "", nil, fmt.Errorf("Error parsing A: %s", ans)
	}
	name, ns := ParseDNSPodName(parts[0])
	ip := net.ParseIP(parts[4])
	if ip == nil {
		return "", "", nil, fmt.Errorf("Error parsing IP address: %s", parts[4])
	}
	return name, ns, ip, nil
}

func ParseDNSPodName(fqdn string) (string, string) {
	parts := strings.Split(fqdn, ".")

	if len(parts) == 7 {
		return parts[1], parts[2]
	}

	return parts[0], parts[1]
}
