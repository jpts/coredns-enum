package util

import (
	"fmt"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress-go/ipaddr/addrstrparam"
)

func ParseIPv4CIDR(cidr string) (*ipaddr.IPAddress, error) {
	pb := addrstrparam.IPAddressStringParamsBuilder{}
	pb.AllowWildcardedSeparator(true)
	pb.AllowIPv4(true)
	pb.AllowIPv6(false)
	pb.AllowMask(true)
	pb.AllowPrefix(true)
	pb.AllowEmpty(false)
	pb.AllowSingleSegment(false)
	params := pb.ToParams()

	ipastr := ipaddr.NewIPAddressStringParams(cidr, params)

	if !ipastr.IsPrefixed() {
		return nil, fmt.Errorf("CIDR %s requires prefix, use /32 for a single host", cidr)
	}

	subnet, err := ipastr.ToAddress()
	if err != nil {
		return nil, err
	}

	return subnet.ToPrefixBlock(), nil
}
