package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/rs/zerolog/log"
)

type cliOpts struct {
	loglevel   int
	maxWorkers int
	cidrRange  string
	nameserver string
	nameport   int
	timeout    float32
	mode       string
	zone       string
	proto      string
}

var opts cliOpts

var rootCmd = &cobra.Command{
	Use:   "coredns-enum",
	Short: "Discover Services & Pods through DNS Records in CoreDNS",
	//SilenceUsage:  true,
	//SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		lvl, err := zerolog.ParseLevel(fmt.Sprint(opts.loglevel))
		if err != nil {
			return errors.New("Error setting up logging")
		}
		zerolog.SetGlobalLevel(lvl)

		if opts.proto != "udp" && opts.proto != "tcp" && opts.proto != "auto" {
			log.Error().Msg("Invalid protocol")
		}

		initDNS()

		if opts.nameserver == "" {
			opts.nameserver, opts.nameport, err = getNSFromSystem()
			if err != nil {
				return err
			}
			log.Info().Msgf("Detected nameserver as %s:%d", opts.nameserver, opts.nameport)
		}

		if opts.mode == MODE_AUTO {
			opts.mode = detectMode()
		}

		var res []*svcResult
		switch opts.mode {
		case MODE_BRUTEFORCE:
			res, err = brute(&opts)
		case MODE_WILDCARD:
			res, err = wildcard(&opts)
		case MODE_FAILED:
			err = fmt.Errorf("Failed to detect mode automatically")
		default:
			err = fmt.Errorf("Unsupported mode: %s", opts.mode)
		}
		if err != nil {
			return err
		}

		renderResults(res)

		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		log.Err(err)
		os.Exit(1)
	}
	os.Exit(0)
}

func init() {
	// global flags
	rootCmd.PersistentFlags().IntVarP(&opts.loglevel, "loglevel", "v", 1, "Set loglevel (-1 => 5)")
	rootCmd.PersistentFlags().StringVarP(&opts.mode, "mode", "m", "auto", "Select mode: wildcard|bruteforce|auto")
	rootCmd.PersistentFlags().StringVar(&opts.zone, "zone", "cluster.local", "DNS zone")

	// bruteforce
	rootCmd.Flags().IntVarP(&opts.maxWorkers, "max-workers", "t", 50, "Number of 'workers' to use for concurrency")
	rootCmd.Flags().StringVar(&opts.cidrRange, "cidr", "", "Range to scan in bruteforce mode")

	// nameserver
	rootCmd.Flags().StringVarP(&opts.nameserver, "nsip", "n", "", "Nameserver to use (detected by default)")
	rootCmd.Flags().IntVar(&opts.nameport, "nsport", 53, "Nameserver port to use (detected by default)")
	rootCmd.Flags().Float32Var(&opts.timeout, "timeout", 0.5, "DNS query timeout (seconds)")
	rootCmd.Flags().StringVar(&opts.proto, "protocol", "auto", "DNS protocol: udp|tcp|auto")
}
