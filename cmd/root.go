package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/rs/zerolog/log"
)

var (
	loglevel   int
	maxWorkers int
	cidrRange  string
	nameserver string
	timeout    float32
)

var rootCmd = &cobra.Command{
	Use:   "enum",
	Short: "",
	Long:  ``,
	//Args:  cobra.MinimumNArgs(1),
	//SilenceUsage:  true,
	//SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// setup logging level
		lvl, err := zerolog.ParseLevel(fmt.Sprint(loglevel))
		if err != nil {
			return err
		}
		zerolog.SetGlobalLevel(lvl)

		_, subnet, err := net.ParseCIDR(cidrRange)
		if err != nil {
			return err
		}

		err = brute(subnet, maxWorkers, nameserver)
		if err != nil {
			return err
		}

		return nil
	},
}

func Execute() {
	// log init
	//initLogger()
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	//zerolog.SetGlobalLevel(zerolog.InfoLevel)

	err := rootCmd.Execute()
	if err != nil {
		log.Err(err).Msg("Unexpected Error")
	}
	os.Exit(0)
}

func init() {
	// global flags
	rootCmd.PersistentFlags().IntVarP(&loglevel, "loglevel", "v", 1, "Set loglevel (-1 => 5)")

	// bruteforce
	rootCmd.Flags().IntVarP(&maxWorkers, "max-workers", "t", 50, "Number of 'workers' to use for concurrency")
	// nameserver
	rootCmd.Flags().StringVar(&cidrRange, "cidr", "", "Range to scan")
	rootCmd.Flags().StringVarP(&nameserver, "nameserver", "n", "", "Nameserver to use")
	rootCmd.Flags().Float32Var(&timeout, "timeout", 0.5, "DNS query timeout")
}
