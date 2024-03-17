package types

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

type QueryResult struct {
	Answers    []dns.RR
	Additional []dns.RR
	Raw        *dns.Msg
	IP         *net.IP
	RTT        *time.Duration
}

type SvcResult struct {
	Name      string
	Namespace string
	IP        *net.IP
	Ports     []*PortResult
	Endpoints []*PodResult
}

func (s *SvcResult) String() string { return fmt.Sprintf("%s/%s", s.Namespace, s.Name) }

type PodResult struct {
	Name      string
	Namespace string
	IP        *net.IP
	Ports     []*PortResult
}

type PortResult struct {
	Proto    string
	PortNo   int
	PortName string
}

func (p *PortResult) String() string { return fmt.Sprintf("%d/%s", p.PortNo, p.Proto) }
