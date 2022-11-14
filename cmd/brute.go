package cmd

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/miekg/dns"
	"github.com/pkg/errors"

	"github.com/rs/zerolog/log"
)

// mode: -auto -wildcard -bruteforce
// ranges: -auto (from cert sans, local ip range) -manual
// workers: specify parallelism
// server: override auto detection of coredns server

// TODO
// initial dns server reachablility check
//  ^ type k8s.default... & pull cert
// automatically

type queryResult struct {
	dnsRR *dns.RR
	raw   *dns.Msg
	ip    *net.IP
	rtt   *time.Duration
}

func brute(subnet *net.IPNet, maxWorkers int, nameserver string) error {

	var server string
	var err error
	if nameserver != "" {
		server = fmt.Sprintf("%s:53", nameserver)
	} else {
		server, err = getNSFromSystem()
		if err != nil {
			return err
		}
		log.Info().Msgf("detected nameserver as %s", server)
	}

	// check nameserver is a RFC1918 address

	// setup DNS client
	c := new(dns.Client)
	dur, _ := time.ParseDuration("0.5s")
	c.Timeout = dur

	first, last := cidr.AddressRange(subnet)
	count := cidr.AddressCount(subnet)
	log.Info().Msgf("scanning range %s to %s, %d hosts", first.String(), last.String(), count)
	//firstInt, _ := strconv.Atoi(strings.Split(first.String(), ".")[3])
	//lastInt, _ := strconv.Atoi(strings.Split(last.String(), ".")[3])
	//for i := firstInt; i < lastInt; i++ {

	// setup scan list
	ipChan := make(chan net.IP)
	go func() {
		for ip := first; !ip.Equal(last); ip = cidr.Inc(ip) {
			ipChan <- ip
		}
		close(ipChan)
	}()

	wg := sync.WaitGroup{}
	resultChan := make(chan queryResult)
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				res, err := query(c, ip, server)
				if err != nil {
					ipChan <- ip
				}
				resultChan <- *res
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		if res.dnsRR != nil {
			ans := *res.dnsRR
			if reflect.TypeOf(*res.dnsRR) == reflect.TypeOf(&dns.PTR{}) {
				parts := strings.Split(ans.String(), "\t")
				fmt.Printf("%s\t%s\n", res.ip, parts[len(parts)-1])
			} else {
				fmt.Printf("[unknown]: %s\n", *res.dnsRR)
			}
		}
	}

	return nil
}

func getNSFromSystem() (string, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", errors.Wrap(err, "error making client from resolv.conf")
	}

	return fmt.Sprintf("%s:%s", conf.Servers[0], conf.Port), nil
}

func query(c *dns.Client, ip net.IP, server string) (*queryResult, error) {

	m := &dns.Msg{
		Question: make([]dns.Question, 1),
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
		},
	}

	revip := strings.Join(reverse(strings.Split(ip.String(), ".")), ".")
	ptr := fmt.Sprintf("%s.in-addr.arpa.", revip)
	fqdn := dns.Fqdn(ptr)

	log.Debug().Msgf("querying %s, %s", ip.String(), fqdn)
	m.Question[0] = dns.Question{
		Name:   fqdn,
		Qtype:  dns.TypePTR,
		Qclass: dns.ClassINET,
	}
	r, rtt, err := c.Exchange(m, server)
	if err != nil {
		var dnsError *net.OpError
		if errors.As(err, &dnsError) && strings.Contains(err.Error(), "timeout") {
			return &queryResult{}, nil
		} else {
			fmt.Printf("error: %s for %s\n", err, ip)
			return nil, err
		}
	}
	if r != nil && len(r.Answer) > 0 {
		return &queryResult{
			dnsRR: &r.Answer[0],
			raw:   r,
			ip:    &ip,
			rtt:   &rtt,
		}, nil
	}

	return &queryResult{}, nil
}

func reverse(numbers []string) []string {
	newNumbers := make([]string, len(numbers))
	for i, j := 0, len(numbers)-1; i <= j; i, j = i+1, j-1 {
		newNumbers[i], newNumbers[j] = numbers[j], numbers[i]
	}
	return newNumbers
}
