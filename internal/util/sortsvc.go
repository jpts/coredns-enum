package util

import "github.com/jpts/coredns-enum/internal/types"

type SortByNsName []*types.SvcResult

func (a SortByNsName) Len() int { return len(a) }

func (a SortByNsName) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func (a SortByNsName) Less(i, j int) bool {
	if a[i].Namespace == a[j].Namespace {
		return a[i].Name < a[j].Name
	}
	return a[i].Namespace < a[j].Namespace
}
