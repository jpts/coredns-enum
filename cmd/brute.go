package cmd

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/rs/zerolog/log"
)

var srvServices = map[string][]string{
	"tcp": {
		"_ceph",
		"_ceph-mon",
		"_certificates",
		"_dns-tcp",
		"_dns-llq",
		"_dns-llq-tls",
		"_dns-push-tls",
		"_dns-update",
		"_dns-update-tls",
		"_ftp",
		"_grpc",
		"_http",
		"_https",
		"_metrics",
		"_nfs-domainroot",
		"_peer-service",
		"_puppet",
		"_sip",
		"_sips",
		"_ssh",
		"_tunnel",
		"_www",
		"_www-http",
		"_xmpp",
		"_xmpp-client",
		"_xmpp-server",
		"_x-puppet",
	},
	"udp": {
		"_chat",
		"_dns",
		"_dns-sd",
		"_dns-llq",
		"_dns-llq-tls",
		"_dns-update",
		"_nfs",
		"_ntp",
		"_sip",
		"_sips",
		"_xmpp-client",
		"_xmpp-server",
	},
}

var ipChan = make(chan net.IP)
var srvChan = make(chan net.IP)
var ptrResultChan = make(chan queryResult)
var svcChan = make(chan svcResult)
var svcResultChan = make(chan svcResult)

func brute(opts *cliOpts) ([]*svcResult, error) {
	var err error
	var subnets []*net.IPNet

	if opts.cidrRange == "" {
		subnets, err = getAPIServerCIDRS()
		if err != nil {
			return nil, err
		}
		log.Info().Msgf("Guessed %s CIDRs from APIserver cert", subnets)
	} else {
		for _, cidr := range strings.Split(opts.cidrRange, ",") {
			_, subnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, err
			}
			subnets = append(subnets, subnet)
		}
	}

	// setup scan list
	go func() {
		for _, net := range subnets {
			first, last := cidr.AddressRange(net)
			count := cidr.AddressCount(net)
			log.Info().Msgf("Scanning range %s to %s, %d hosts", first.String(), last.String(), count)
			for ip := first; !ip.Equal(last); ip = cidr.Inc(ip) {
				ipChan <- ip
			}
		}
		close(ipChan)
	}()

	// parallelise ptr query scanning
	wg := sync.WaitGroup{}
	wg.Add(opts.maxWorkers)
	for w := 0; w < opts.maxWorkers; w++ {
		go ptrQueryWorker(&wg)
	}

	go func() {
		wg.Wait()
		close(ptrResultChan)
	}()

	// recv results async
	go func() {
		for res := range ptrResultChan {
			if res.answers != nil {
				ans := res.answers[0]
				parts := strings.Split(ans.String(), "\t")
				name, ns := parseDNSPodName(parts[len(parts)-1])
				log.Debug().Msgf("Processing svc: %s\t%s", res.ip, parts[len(parts)-1])
				svc := svcResult{
					Name:      name,
					Namespace: ns,
					IP:        res.ip,
				}
				svcChan <- svc
			}
		}
		close(svcChan)
	}()

	// parallelise service port bruteforcing
	wg2 := sync.WaitGroup{}
	wg2.Add(opts.maxWorkers)
	for w := 0; w < opts.maxWorkers; w++ {
		go svcPortScanWorker(&wg2)
	}

	go func() {
		wg2.Wait()
		close(svcResultChan)
	}()

	var svcs []*svcResult
	for res := range svcResultChan {
		// new object needed as objects are clobbered in channel range
		obj := &svcResult{
			Name:      res.Name,
			Namespace: res.Namespace,
			IP:        res.IP,
			Ports:     res.Ports,
			Endpoints: res.Endpoints,
		}
		svcs = append(svcs, obj)
	}

	return svcs, nil
}

func ptrQueryWorker(wg *sync.WaitGroup) {
	for ip := range ipChan {
		res, err := queryPTR(ip)
		if err != nil {
			log.Info().Msgf("Retrying failed ip %s: %s", ip, err.Error())
			ipChan <- ip
		}
		if res == nil {
			continue
		}
		ptrResultChan <- *res
	}
	wg.Done()
}

func svcPortScanWorker(wg *sync.WaitGroup) {
	for svc := range svcChan {
		for proto, srvSvcList := range srvServices {
			for _, svcName := range srvSvcList {
				res, err := querySRV(fmt.Sprintf("%s._%s.%s.%s.svc.%s",
					svcName,
					proto,
					svc.Name,
					svc.Namespace,
					opts.zone,
				))
				if err != nil {
					log.Warn().Msgf("SRV request failed %s/%s: %s", svcName, proto, err.Error())
					svcResultChan <- svc
				}
				if res == nil {
					continue
				}
				for _, ans := range res.answers {
					_, _, port, err := parseSRVAnswer(ans.String())
					if err != nil {
						log.Warn().Err(err)
						continue
					}

					addPortToSvc(&svc, proto, port, svcName)
					log.Debug().Msgf("Found port for svc: %d/%s/%s", port, proto, svcName)
				}
			}
		}
		svcResultChan <- svc
	}

	wg.Done()
}

func reverse(numbers []string) []string {
	newNumbers := make([]string, len(numbers))
	for i, j := 0, len(numbers)-1; i <= j; i, j = i+1, j-1 {
		newNumbers[i], newNumbers[j] = numbers[j], numbers[i]
	}
	return newNumbers
}

func isElement(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
