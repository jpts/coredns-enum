package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

const (
	MODE_AUTO       = "auto"
	MODE_BRUTEFORCE = "bruteforce"
	MODE_WILDCARD   = "wildcard"
	MODE_FAILED     = "failed"
)

func detectMode() string {
	if ok, _ := checkSpecVersion(); !ok {
		log.Info().Msg("Unable to detect spec compliant Kubernetes DNS server")
		return MODE_FAILED
	}

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

func checkSpecVersion() (bool, error) {
	res, err := queryTXT(fmt.Sprintf("dns-version.%s", opts.zone))
	if err != nil {
		return false, err
	}

	return res != nil, nil
}

func queryDefaultK8sAddress() (bool, error) {
	res, err := queryA(fmt.Sprintf("kubernetes.default.svc.%s", opts.zone))
	if err != nil {
		return false, err
	}

	return res != nil, nil
}

func wildcardK8sAddress() (bool, error) {
	res, err := queryA(fmt.Sprintf("any.any.svc.%s", opts.zone))
	if err != nil {
		return false, err
	}

	return res != nil, nil
}

func getDefaultAPIServerCert() (*x509.Certificate, error) {
	if ok, err := queryDefaultK8sAddress(); !ok || err != nil {
		return nil, fmt.Errorf("couldnt query default apiserver")
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("kubernetes.default.svc.%s:443", opts.zone), conf)
	if err != nil {
		return nil, fmt.Errorf("Error in connecting to API server")
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	// assume one
	cert := certs[0]

	if cert.Issuer.CommonName != "kubernetes" {
		return nil, fmt.Errorf("problem getting apiserver cert")
	}

	// look at kubernetes.default and kube-dns.kube-system to determine pod/node networks
	return cert, nil
}

func isPrivateAddress(addr *ipaddr.IPAddress) bool {
	// RFC6598 CGN Shared IP Range
	SHARED_CIDR_RANGES := []*ipaddr.IPAddressString{
		ipaddr.NewIPAddressString("100.64.0.0/10"),
	}
	// RFC3330,RFC2544 Test Nets
	TEST_CIDR_RANGES := []*ipaddr.IPAddressString{
		ipaddr.NewIPAddressString("192.0.2.0/24"),
		ipaddr.NewIPAddressString("198.18.0.0/15"),
		ipaddr.NewIPAddressString("198.51.100.0/24"),
		ipaddr.NewIPAddressString("203.0.113.0/24"),
	}

	if addr.ToIPv4().IsPrivate() {
		return true
	}

	for _, cidrstr := range append(SHARED_CIDR_RANGES, TEST_CIDR_RANGES...) {
		cidr := cidrstr.GetAddress()
		if cidr.Contains(addr) {
			return true
		}
	}

	return false
}

func GetAPIServerCIDRS(cert *x509.Certificate) ([]*ipaddr.IPAddress, error) {
	var cidrs []*ipaddr.IPAddress
	for _, ip := range cert.IPAddresses {
		net, err := ipaddr.NewIPAddressFromNetIP(ip)
		if err != nil {
			return nil, fmt.Errorf("problem parsing apiserver cert IPs: %s", ip)
		}
		// Guess subnet size and set network addr
		net = net.ToPrefixBlockLen(22)

		if !isPrivateAddress(net) {
			log.Debug().Msgf("CIDR %s not private, removing from guesses", net)
			continue
		}

		cidrs = append(cidrs, net)
	}

	return cidrs, nil
}
