package types

type CliOpts struct {
	LogLevel   int
	MaxWorkers int
	CidrRange  string
	Nameserver string
	Nameport   int
	Timeout    float32
	Mode       string
	Zone       string
	Proto      string
}
