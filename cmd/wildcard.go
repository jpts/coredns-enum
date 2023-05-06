package cmd

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// https://github.com/coredns/coredns.io/blob/1.8.4/content/plugins/kubernetes.md#wildcards

func wildcard(opts *cliOpts) ([]*svcResult, error) {
	var svcs []*svcResult

	// port/proto - gives us namespaces
	for _, proto := range []string{"tcp", "udp"} {
		res, err := querySRV(fmt.Sprintf("any._%s.any.any.svc.%s", proto, opts.zone))
		if err != nil {
			return nil, err
		}

		if len(res.raw.Extra) == 0 {
			log.Debug().Msgf("No svcs for proto %s found", proto)
			continue
		}
		for _, rr := range res.additional {
			name, ns, ip, err := parseAAnswer(rr.String())
			if err != nil {
				return nil, err
			}

			svc := &svcResult{
				Name:      name,
				Namespace: ns,
				IP:        &ip,
			}
			svcs, _ = addUniqueSvcToSvcs(svcs, svc)
		}

		if len(res.answers) == 0 {
			log.Debug().Msgf("No named ports for %s svcs found", proto)
			continue
		}
		for _, rr := range res.answers {
			name, ns, port, err := parseSRVAnswer(rr.String())
			if err != nil {
				return nil, err
			}
			addPortToSvcs(svcs, name, ns, proto, port, "")
		}
	}

	// endpoints
	for _, svc := range svcs {
		res, err := queryA(fmt.Sprintf("any.%s.%s.svc.%s", svc.Name, svc.Namespace, opts.zone))
		if err != nil {
			log.Warn().Err(err)
			continue
		}

		if len(res.answers) == 0 {
			log.Debug().Msgf("svc %s/%s has no registered endpoints", svc.Namespace, svc.Name)
			continue
		}
		for _, rr := range res.answers {
			_, _, ip, err := parseAAnswer(rr.String())
			if err != nil {
				log.Warn().Err(err)
				continue
			}
			endp := &podResult{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				IP:        &ip,
			}
			svc.Endpoints = append(svc.Endpoints, endp)
		}
	}

	return svcs, nil
}

func addUniqueSvcToSvcs(svcs []*svcResult, svc *svcResult) ([]*svcResult, error) {
	for _, s := range svcs {
		if s.Name == svc.Name && s.Namespace == svc.Namespace && s.IP.String() == svc.IP.String() {
			log.Debug().Msgf("svc %s/%s already registered", svc.Namespace, svc.Name)
			return svcs, nil
		}
	}
	log.Debug().Msgf("adding svc: %s/%s", svc, svc.IP.String())
	return append(svcs, svc), nil
}

func addPortToSvcs(svcs []*svcResult, podName string, ns string, proto string, port int, portName string) error {
	for _, s := range svcs {
		if s.Name == podName && s.Namespace == ns {
			return addPortToSvc(s, proto, port, portName)
		}
	}
	log.Warn().Msgf("could not find svc match for %s/%s", ns, podName)
	return nil
}

func addPortToSvc(svc *svcResult, proto string, port int, portName string) error {
	p := &portResult{
		Proto:    strings.TrimPrefix(proto, "_"),
		PortNo:   port,
		PortName: strings.TrimPrefix(portName, "_"),
	}
	svc.Ports = append(svc.Ports, p)
	return nil
}
