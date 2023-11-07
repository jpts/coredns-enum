package dnsclient

import (
	"fmt"

	"github.com/rs/zerolog/log"
)

const (
	MODE_AUTO       = "auto"
	MODE_BRUTEFORCE = "bruteforce"
	MODE_WILDCARD   = "wildcard"
	MODE_FAILED     = "failed"
)

func (d *DNSClient) DetectMode() string {
	if ok, _ := d.CheckSpecVersion(); !ok {
		log.Info().Msg("Unable to detect spec compliant Kubernetes DNS server")
		return MODE_FAILED
	}

	if ok, _ := d.CheckWildcardK8sAddress(); ok {
		log.Info().Msg("Wildcard support detected")
		return MODE_WILDCARD
	}

	if ok, _ := d.CheckDefaultK8sAddress(); ok {
		log.Info().Msg("Falling back to bruteforce mode")
		return MODE_BRUTEFORCE
	}

	log.Error().Msg("Failed to detect a CoreDNS server")
	return MODE_FAILED
}

func (d *DNSClient) CheckSpecVersion() (bool, error) {
	res, err := d.QueryTXT(fmt.Sprintf("dns-version.%s", d.CliOpts.Zone))
	if err != nil {
		return false, err
	}

	return res != nil, nil
}

func (d *DNSClient) CheckDefaultK8sAddress() (bool, error) {
	res, err := d.QueryA(fmt.Sprintf("kubernetes.default.svc.%s", d.CliOpts.Zone))
	if err != nil {
		return false, err
	}

	return res != nil, nil
}

func (d *DNSClient) CheckWildcardK8sAddress() (bool, error) {
	res, err := d.QueryA(fmt.Sprintf("any.any.svc.%s", d.CliOpts.Zone))
	if err != nil {
		return false, err
	}

	return res != nil, nil
}
