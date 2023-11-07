package util

import (
	"fmt"
	"os"
	"sort"

	"github.com/jpts/coredns-enum/internal/types"
	"github.com/olekukonko/tablewriter"
)

func RenderResults(res []*types.SvcResult) {
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
