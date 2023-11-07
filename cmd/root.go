package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/jpts/coredns-enum/internal/types"
	"github.com/jpts/coredns-enum/internal/util"
	"github.com/jpts/coredns-enum/pkg/dnsclient"
	"github.com/jpts/coredns-enum/pkg/scanners"
)

var opts types.CliOpts

var rootCmd = &cobra.Command{
	Use:   "coredns-enum",
	Short: "Discover Services & Pods through DNS Records in CoreDNS",
	//SilenceUsage:  true,
	//SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		lvl, err := zerolog.ParseLevel(fmt.Sprint(opts.LogLevel))
		if err != nil {
			return errors.New("Error setting up logging")
		}
		zerolog.SetGlobalLevel(lvl)

		if opts.Proto != "udp" && opts.Proto != "tcp" && opts.Proto != "auto" {
			log.Error().Msg("Invalid protocol")
		}

		dclient := dnsclient.InitDNS(&opts)

		if opts.Nameserver == "" {
			opts.Nameserver, opts.Nameport, err = dclient.GetNSFromSystem()
			if err != nil {
				return err
			}
			log.Info().Msgf("Detected nameserver as %s:%d", opts.Nameserver, opts.Nameport)
		}

		if opts.Mode == dnsclient.MODE_AUTO {
			opts.Mode = dclient.DetectMode()
		}

		var res []*types.SvcResult
		switch opts.Mode {
		case dnsclient.MODE_BRUTEFORCE:
			res, err = scanners.BruteScan(&opts, dclient)
		case dnsclient.MODE_WILDCARD:
			res, err = scanners.WildcardScan(&opts, dclient)
		case dnsclient.MODE_FAILED:
			err = fmt.Errorf("Failed to detect mode automatically")
		default:
			err = fmt.Errorf("Unsupported mode: %s", opts.Mode)
		}
		if err != nil {
			return err
		}

		util.RenderResults(res)

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
	rootCmd.PersistentFlags().IntVarP(&opts.LogLevel, "loglevel", "v", 1, "Set loglevel (-1 => 5)")
	rootCmd.PersistentFlags().StringVarP(&opts.Mode, "mode", "m", "auto", "Select mode: wildcard|bruteforce|auto")
	rootCmd.PersistentFlags().StringVar(&opts.Zone, "zone", "cluster.local", "DNS zone")

	// bruteforce
	rootCmd.Flags().IntVarP(&opts.MaxWorkers, "max-workers", "t", 50, "Number of 'workers' to use for concurrency")
	rootCmd.Flags().StringVar(&opts.CidrRange, "cidr", "", "Range to scan in bruteforce mode")

	// nameserver
	rootCmd.Flags().StringVarP(&opts.Nameserver, "nsip", "n", "", "Nameserver to use (detected by default)")
	rootCmd.Flags().IntVar(&opts.Nameport, "nsport", 53, "Nameserver port to use (detected by default)")
	rootCmd.Flags().Float32Var(&opts.Timeout, "timeout", 0.5, "DNS query timeout (seconds)")
	rootCmd.Flags().StringVar(&opts.Proto, "protocol", "auto", "DNS protocol: udp|tcp|auto")
}
