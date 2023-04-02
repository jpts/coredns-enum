package cmd

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
)

const (
	MODE_AUTO       = "auto"
	MODE_BRUTEFORCE = "bruteforce"
	MODE_WILDCARD   = "wildcard"
	MODE_FAILED     = "failed"
)

func detectMode() string {
	if ok, _ := wildcardK8sAddress(); ok {
		log.Info().Msg("Wildcard support detected")
		return MODE_WILDCARD
	}
	if ok, _ := queryDefaultK8sAddress(); ok {
		log.Info().Msg("Falling back to bruteforce mode")
		return MODE_BRUTEFORCE
	}
	log.Error().Msg("Failed to detect a CoreDNS server")
	return MODE_FAILED
}

func queryDefaultK8sAddress() (bool, error) {
	res, err := queryA(fmt.Sprintf("kubernetes.default.svc.%s", opts.zone))
	if err != nil {
		return false, err
	}

	return res.raw != nil, nil
}

func wildcardK8sAddress() (bool, error) {
	res, err := queryA(fmt.Sprintf("any.any.svc.%s", opts.zone))
	if err != nil {
		return false, err
	}

	return res.raw != nil, nil
}

func getAPIServerCIDRS() ([]*net.IPNet, error) {
	var cidrs []*net.IPNet

	if ok, err := queryDefaultK8sAddress(); !ok || err != nil {
		return nil, fmt.Errorf("couldnt query default apiserver")
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("kubernetes.default.svc.%s:443", opts.zone), conf)
	if err != nil {
		log.Err(err).Msg("Error in Dial")
		return cidrs, nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	cert := certs[0]

	if cert.Issuer.CommonName != "kubernetes" {
		return cidrs, fmt.Errorf("problem getting apiserver cert")
	}

	// look at kubernetes.default and kube-dns.kube-system to determine pod/node networks

	for _, ip := range cert.IPAddresses {
		cidrs = append(cidrs, &net.IPNet{
			IP: ip,
			// Take a best guess here
			Mask: net.IPv4Mask(255, 255, 252, 0),
		})
	}

	return cidrs, nil
}
