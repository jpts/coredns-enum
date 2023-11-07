package dnsclient

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAAnswer(t *testing.T) {
	cases := []map[string]any{
		{
			"in": "kubernetes.default.svc.cluster.local.\t5\tIN\tA\t10.100.0.1",
			"out": map[string]any{
				"name": "kubernetes",
				"ns":   "default",
				"ip":   net.ParseIP("10.100.0.1"),
			},
		},
		{
			"in": "kube-dns.kube-system.svc.cluster.local.\t5\tIN\tA\t10.100.0.10",
			"out": map[string]any{
				"name": "kube-dns",
				"ns":   "kube-system",
				"ip":   net.ParseIP("10.100.0.10"),
			},
		},
	}

	for _, tcase := range cases {
		in := tcase["in"].(string)
		out := tcase["out"].(map[string]any)

		name, ns, ip, err := ParseAAnswer(in)

		assert.Equal(t, out["name"], name)
		assert.Equal(t, out["ns"], ns)
		assert.Equal(t, out["ip"], ip)
		assert.Nil(t, err)
	}
}

func TestParseSRVAnswer(t *testing.T) {
	cases := []map[string]any{
		{
			"in": "kubernetes.default.svc.cluster.local.\t5\tIN\tSRV\t0 100 443 kubernetes.default.svc.cluster.local.",
			"out": map[string]any{
				"name": "kubernetes",
				"ns":   "default",
				"port": 443,
			},
		},
		{
			"in": "_dns._udp.kube-dns.kube-system.svc.cluster.local.\t5\tIN\tSRV\t0 100 53 kube-dns.kube-system.svc.cluster.local.",
			"out": map[string]any{
				"name": "kube-dns",
				"ns":   "kube-system",
				"port": 53,
			},
		},
	}

	for _, tcase := range cases {
		in := tcase["in"].(string)
		out := tcase["out"].(map[string]any)

		name, ns, port, err := ParseSRVAnswer(in)

		assert.Equal(t, out["name"], name)
		assert.Equal(t, out["ns"], ns)
		assert.Equal(t, out["port"], port)
		assert.Nil(t, err)
	}
}
