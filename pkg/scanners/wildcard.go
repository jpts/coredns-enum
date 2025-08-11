package scanners

import (
	"fmt"
	"strings"

	"github.com/jpts/coredns-enum/pkg/dnsclient"
	"github.com/jpts/coredns-enum/pkg/types"
	"github.com/rs/zerolog/log"
)

// https://github.com/coredns/coredns.io/blob/1.8.4/content/plugins/kubernetes.md#wildcards

func WildcardScan(opts *types.CliOpts, dclient *dnsclient.DNSClient) ([]*types.SvcResult, error) {
	var svcs []*types.SvcResult

	// port/proto - gives us namespaces
	for _, proto := range []string{"tcp", "udp"} {
		res, err := dclient.QuerySRV(fmt.Sprintf("any._%s.any.any.svc.%s", proto, opts.Zone))
		if err != nil {
			return nil, err
		}

		if res == nil || res.Additional == nil {
			log.Debug().Msgf("No svcs for proto %s found", proto)
			continue
		}
		for _, rr := range res.Additional {
			name, ns, ip, err := dnsclient.ParseAAnswer(rr.String())
			if err != nil {
				return nil, err
			}

			svc := &types.SvcResult{
				Name:      name,
				Namespace: ns,
				IP:        &ip,
			}
			svcs, _ = addUniqueSvcToSvcs(svcs, svc)
		}

		if res.Answers == nil {
			log.Debug().Msgf("No named ports for %s svcs found", proto)
			continue
		}
		for _, rr := range res.Answers {
			name, ns, port, err := dnsclient.ParseSRVAnswer(rr.String())
			if err != nil {
				return nil, err
			}
			addPortToSvcs(svcs, name, ns, proto, port, "")
		}
	}

	// endpoints
	for _, svc := range svcs {
		res, err := dclient.QueryA(fmt.Sprintf("any.%s.%s.svc.%s", svc.Name, svc.Namespace, opts.Zone))
		if err != nil {
			log.Warn().Err(err)
			continue
		}

		if res == nil || res.Answers == nil {
			log.Debug().Msgf("svc %s/%s has no registered endpoints", svc.Namespace, svc.Name)
			continue
		}
		for _, rr := range res.Answers {
			_, _, ip, err := dnsclient.ParseAAnswer(rr.String())
			if err != nil {
				log.Warn().Err(err)
				continue
			}
			endp := &types.PodResult{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				IP:        &ip,
			}
			svc.Endpoints = append(svc.Endpoints, endp)
		}
	}

	return svcs, nil
}

func addUniqueSvcToSvcs(svcs []*types.SvcResult, svc *types.SvcResult) ([]*types.SvcResult, error) {
	for _, s := range svcs {
		if s.Name == svc.Name && s.Namespace == svc.Namespace && s.IP.String() == svc.IP.String() {
			log.Debug().Msgf("svc %s/%s already registered", svc.Namespace, svc.Name)
			return svcs, nil
		}
	}
	log.Debug().Msgf("adding svc: %s/%s", svc, svc.IP.String())
	return append(svcs, svc), nil
}

func addPortToSvcs(svcs []*types.SvcResult, podName string, ns string, proto string, port int, portName string) error {
	for _, s := range svcs {
		if s.Name == podName && s.Namespace == ns {
			return addPortToSvc(s, proto, port, portName)
		}
	}
	log.Warn().Msgf("could not find svc match for %s/%s", ns, podName)
	return nil
}

func addPortToSvc(svc *types.SvcResult, proto string, port int, portName string) error {
	p := &types.PortResult{
		Proto:    strings.TrimPrefix(proto, "_"),
		PortNo:   port,
		PortName: strings.TrimPrefix(portName, "_"),
	}
	svc.Ports = append(svc.Ports, p)
	return nil
}
