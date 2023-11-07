package scanners

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	"github.com/stretchr/testify/assert"
)

func getnets(nets []string) []*ipaddr.IPAddress {
	ipnets := []*ipaddr.IPAddress{}

	for _, netw := range nets {
		ip := strings.Split(netw, "/")[0]
		mask := strings.Split(netw, "/")[1]
		maskint, _ := strconv.Atoi(mask)

		ipanet, err := ipaddr.NewIPAddressString(ip).ToAddress()
		if err != nil {
			return nil
		}
		// ipanet = ipanet.SetPrefixLen(maskint)
		// Ideally we'd set isMult directly
		ipanet = ipanet.ToPrefixBlockLen(maskint)

		ipnets = append(ipnets, ipanet)
	}
	return ipnets
}

func getnetips(ipstrs []string) []net.IP {
	ips := []net.IP{}

	for _, ipstr := range ipstrs {
		ip := net.ParseIP(ipstr)
		ips = append(ips, ip)
	}
	return ips
}

func genCertForNets(ips []net.IP) (*x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "kubernetes",
		},
		IPAddresses: ips,
		DNSNames:    []string{"kubernetes.default.svc.cluter.local"},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Self-sign the certificate
	certificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, err
	}

	// throw away the priv key
	return certificate, nil
}

func TestGetApiServerCIDRS(t *testing.T) {
	cases := []map[string][]string{
		{
			"in":  []string{"10.100.0.1"},
			"out": []string{"10.100.0.0/22"},
		},
		{
			"in":  []string{"10.100.0.1", "10.96.0.1"},
			"out": []string{"10.100.0.0/22", "10.96.0.0/22"},
		},
		{
			"in":  []string{"10.100.0.1", "10.96.0.1", "34.56.128.129"},
			"out": []string{"10.100.0.0/22", "10.96.0.0/22"},
		},
		{
			"in":  []string{"10.100.0.1", "172.16.31.1"},
			"out": []string{"10.100.0.0/22", "172.16.28.0/22"},
		},
		{
			"in":  []string{"10.100.0.253", "100.64.13.14"},
			"out": []string{"10.100.0.0/22", "100.64.12.0/22"},
		},
	}

	for _, tcase := range cases {
		netips := getnetips(tcase["in"])
		ipnetsout := getnets(tcase["out"])

		cert, err := genCertForNets(netips)
		if err != nil {
			fmt.Println(err)
		}

		actual, err := GetAPIServerCIDRS(cert)
		if err != nil {
			fmt.Println(err)
		}

		assert.Equal(t, ipnetsout, actual)
		assert.Nil(t, err)
	}
}
