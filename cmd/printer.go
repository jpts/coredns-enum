package cmd

import (
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	"github.com/miekg/dns"
	"github.com/olekukonko/tablewriter"
)

type queryResult struct {
	answers    []dns.RR
	additional []dns.RR
	raw        *dns.Msg
	ip         *net.IP
	rtt        *time.Duration
}

type svcResult struct {
	Name      string
	Namespace string
	IP        *net.IP
	Ports     []*portResult
	Endpoints []*podResult
}

func (s *svcResult) String() string { return fmt.Sprintf("%s/%s", s.Namespace, s.Name) }

type podResult struct {
	Name      string
	Namespace string
	IP        *net.IP
	Ports     []*portResult
}

type portResult struct {
	Proto    string
	PortNo   int
	PortName string
}

func (p *portResult) String() string { return fmt.Sprintf("%d/%s", p.PortNo, p.Proto) }

type SortByNsName []*svcResult

func (a SortByNsName) Len() int { return len(a) }

func (a SortByNsName) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func (a SortByNsName) Less(i, j int) bool {
	if a[i].Namespace == a[j].Namespace {
		return a[i].Name < a[j].Name
	}
	return a[i].Namespace < a[j].Namespace
}

func renderResults(res []*svcResult) {
	var output [][]string

	sort.Sort(SortByNsName(res))

	for _, svc := range res {
		var svcLines []string
		var endpLines []string
		for _, port := range svc.Ports {
			if port.PortName != "" {
				svcLines = append(svcLines, fmt.Sprintf("%d/%s (%s)",
					port.PortNo,
					port.Proto,
					port.PortName,
				))
			} else {
				svcLines = append(svcLines, fmt.Sprintf("%d/%s",
					port.PortNo,
					port.Proto,
				))
			}
		}
		if len(svc.Ports) == 0 {
			svcLines = []string{"??"}
		}

		for _, endp := range svc.Endpoints {
			endpLines = append(endpLines, endp.IP.String())
		}

		for i := 0; i < max(len(svcLines), len(endpLines)); i++ {
			line := []string{
				svc.Namespace,
				svc.Name,
				svc.IP.String(),
				safeIndex(svcLines, i),
				safeIndex(endpLines, i),
			}
			output = append(output, line)
		}
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoMergeCellsByColumnIndex([]int{0, 1, 2})
	//table.SetRowLine(true)
	table.SetHeader([]string{"Namespace", "Name", "SVC IP", "SVC Port", "Endpoints"})
	table.AppendBulk(output)
	table.Render()
}

func safeIndex(arr []string, index int) string {
	if index > len(arr)-1 {
		return ""
	}
	return arr[index]
}

func max(i, j int) int {
	if i > j {
		return i
	}
	return j
}
