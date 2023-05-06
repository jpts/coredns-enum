# CoreDNS Enum

A tool to enumerate Kubernetes network information through DNS alone. It attempts to list service IPs, ports, and service endpoint IPs where possible.

The tool has two modes: wildcard & bruteforce. It will automagically detect if the DNS server you are targeting supports CoreDNS wildcards (< v1.9.0) and fallback to the bruteforce method if not. The bruteforce mode also tries to guess sensible CIDR ranges to scan by default (through parsing the API server HTTPS certificate). You can override this.

NB: Bruteforce mode should work against any DNS server compliant to the [Kubernetes DNS Spec](https://github.com/kubernetes/dns/blob/master/docs/specification.md).


```
Usage:
  coredns-enum [flags]

Flags:
      --cidr string       Range to scan in bruteforce mode
  -h, --help              help for coredns-enum
  -v, --loglevel int      Set loglevel (-1 => 5) (default 1)
  -t, --max-workers int   Number of 'workers' to use for concurrency (default 50)
  -m, --mode string       Select mode: wildcard|bruteforce|auto (default "auto")
  -n, --nsip string       Nameserver to use (detected by default)
      --nsport int        Nameserver port to use (detected by default) (default 53)
      --protocol string   DNS protocol: udp|tcp|auto (default "auto")
      --timeout float32   DNS query timeout (seconds) (default 0.5)
      --zone string       DNS zone (default "cluster.local")
```
