package scanners

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

func GetDefaultAPIServerCert(zone string) (*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("kubernetes.default.svc.%s:443", zone), conf)
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
