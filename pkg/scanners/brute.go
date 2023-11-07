package scanners

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/seancfoley/ipaddress-go/ipaddr"

	"github.com/jpts/coredns-enum/internal/types"
	"github.com/jpts/coredns-enum/internal/util"
	"github.com/jpts/coredns-enum/pkg/dnsclient"
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
var ptrResultChan = make(chan types.QueryResult)
var svcChan = make(chan types.SvcResult)
var svcResultChan = make(chan types.SvcResult)

func BruteScan(opts *types.CliOpts, dclient *dnsclient.DNSClient) ([]*types.SvcResult, error) {
	var subnets []*ipaddr.IPAddress

	if opts.CidrRange == "" {
		cert, err := GetDefaultAPIServerCert(dclient.CliOpts.Zone)
		if err != nil {
			return nil, err
		}
		subnets, err = GetAPIServerCIDRS(cert)
		if err != nil {
			return nil, err
		}

		log.Info().Msgf("Guessed %s CIDRs from APIserver cert", subnets)
	} else {
		for _, cidr := range strings.Split(opts.CidrRange, ",") {
			subnet, err := util.ParseIPv4CIDR(cidr)
			if err != nil {
				return nil, err
			}

			subnets = append(subnets, subnet)
		}
	}

	// setup scan list
	go func() {
		for _, net := range subnets {
			iprange := net.ToSequentialRange()

			log.Info().Msgf("Scanning range %s to %s, %d hosts", iprange.GetLower(), iprange.GetUpper(), iprange.GetCount())
			for ip := iprange.Iterator(); ip.HasNext(); {
				ipChan <- ip.Next().GetNetIP()
			}
		}
		close(ipChan)
	}()

	// parallelise ptr dnsclient.Query scanning
	wg := sync.WaitGroup{}
	wg.Add(opts.MaxWorkers)
	for w := 0; w < opts.MaxWorkers; w++ {
		go ptrQueryWorker(&wg, dclient)
	}

	go func() {
		wg.Wait()
		close(ptrResultChan)
	}()

	// recv results async
	go func() {
		for res := range ptrResultChan {
			if res.Answers != nil {
				ans := res.Answers[0]
				parts := strings.Split(ans.String(), "\t")
				name, ns := dnsclient.ParseDNSPodName(parts[len(parts)-1])
				log.Debug().Msgf("Processing svc: %s\t%s", res.IP, parts[len(parts)-1])
				svc := types.SvcResult{
					Name:      name,
					Namespace: ns,
					IP:        res.IP,
				}
				svcChan <- svc
			}
		}
		close(svcChan)
	}()

	// parallelise service port bruteforcing
	wg2 := sync.WaitGroup{}
	wg2.Add(opts.MaxWorkers)
	for w := 0; w < opts.MaxWorkers; w++ {
		go svcPortScanWorker(&wg2, dclient)
	}

	go func() {
		wg2.Wait()
		close(svcResultChan)
	}()

	var svcs []*types.SvcResult
	for res := range svcResultChan {
		// new object needed as objects are clobbered in channel range
		obj := &types.SvcResult{
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

func ptrQueryWorker(wg *sync.WaitGroup, dclient *dnsclient.DNSClient) {
	for ip := range ipChan {
		res, err := dclient.QueryPTR(ip)
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

func svcPortScanWorker(wg *sync.WaitGroup, dclient *dnsclient.DNSClient) {
	for svc := range svcChan {
		for proto, srvSvcList := range srvServices {
			for _, svcName := range srvSvcList {
				res, err := dclient.QuerySRV(fmt.Sprintf("%s._%s.%s.%s.svc.%s",
					svcName,
					proto,
					svc.Name,
					svc.Namespace,
					dclient.CliOpts.Zone,
				))
				if err != nil {
					log.Warn().Msgf("SRV request failed %s/%s: %s", svcName, proto, err.Error())
					svcResultChan <- svc
				}
				if res == nil {
					continue
				}
				for _, ans := range res.Answers {
					_, _, port, err := dnsclient.ParseSRVAnswer(ans.String())
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
