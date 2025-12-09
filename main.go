package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/user/jwt-decode/decoder"
	"github.com/user/jwt-decode/formatter"
)

var (
	filePath   string
	compact    bool
	showRaw    bool
	noColor    bool
)

var rootCmd = &cobra.Command{
	Use:   "jwt-decode [token]",
	Short: "Decode and inspect JWT tokens",
	Long:  "A CLI utility to decode and inspect JWT tokens without verification for debugging authentication issues.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  run,
}

func init() {
	rootCmd.Flags().StringVarP(&filePath, "file", "f", "", "Read token from file")
	rootCmd.Flags().BoolVarP(&compact, "compact", "c", false, "Compact JSON output")
	rootCmd.Flags().BoolVarP(&showRaw, "raw", "r", false, "Show raw base64 segments")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
}

func run(cmd *cobra.Command, args []string) error {
	if noColor {
		color.NoColor = true
	}

	token, err := getToken(args)
	if err != nil {
		return err
	}

	jwt, err := decoder.Decode(token)
	if err != nil {
		return fmt.Errorf("failed to decode token: %w", err)
	}

	formatter.Print(jwt, compact, showRaw)
	return nil
}

func getToken(args []string) (string, error) {
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	if len(args) > 0 {
		return args[0], nil
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		reader := bufio.NewReader(os.Stdin)
		data, err := io.ReadAll(reader)
		if err != nil {
			return "", fmt.Errorf("failed to read stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	return "", fmt.Errorf("no token provided: use argument, --file, or pipe via stdin")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}
