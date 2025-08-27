package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile    string
	serverURL  string
	verbose    bool
)

var rootCmd = &cobra.Command{
	Use:   "basestamp",
	Short: "BaseStamp - A blockchain timestamping service",
	Long: `BaseStamp is a blockchain timestamping service that allows you to create
cryptographic proofs of existence for files by anchoring their hashes
to various blockchain networks including BASE, Ethereum, and others.

Available Commands:
  stamp    Create a timestamp proof for a file
  verify   Verify a timestamp proof for a file

Use "basestamp [command] --help" for more information about a command.`,
	Example: `  # Stamp a file (creates document.pdf.basestamp automatically)
  basestamp stamp document.pdf

  # Stamp with custom output
  basestamp stamp document.pdf -o document.stamp

  # Verify a file (uses document.pdf.basestamp automatically)
  basestamp verify document.pdf

  # Verify with specific stamp file
  basestamp verify document.pdf document.stamp

  # Use local development server
  basestamp stamp document.pdf --server http://localhost:8080`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.basestamp.yaml)")
	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "https://api.basestamp.io", "BaseStamp server URL")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	_ = viper.BindPFlag("server", rootCmd.PersistentFlags().Lookup("server"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".basestamp")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	}
}