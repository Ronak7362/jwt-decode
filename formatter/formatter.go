package formatter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/user/jwt-decode/decoder"
)

func Print(jwt *decoder.JWT, compact, showRaw bool) {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)

	green.Println("\n✓ JWT Token Decoded Successfully")
	fmt.Println()

	if showRaw {
		cyan.Println("Raw Segments:")
		fmt.Printf("  Header:    %s\n", jwt.Segments[0])
		fmt.Printf("  Payload:   %s\n", jwt.Segments[1])
		fmt.Printf("  Signature: %s\n", jwt.Segments[2])
		fmt.Println()
	}

	cyan.Println("Header:")
	printJSON(jwt.Header, compact)
	fmt.Println()

	cyan.Println("Payload:")
	printJSON(jwt.Payload, compact)
	fmt.Println()

	printTimeClaims(jwt, yellow, red)
}

func printJSON(data map[string]interface{}, compact bool) {
	var output []byte
	var err error

	if compact {
		output, err = json.Marshal(data)
	} else {
		output, err = json.MarshalIndent(data, "", "  ")
	}

	if err != nil {
		fmt.Printf("  Error formatting JSON: %v\n", err)
		return
	}

	fmt.Println(string(output))
}

func printTimeClaims(jwt *decoder.JWT, yellow, red *color.Color) {
	if exp, ok := jwt.Payload["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if jwt.IsExpired() {
			red.Printf("⚠ Expired: %s (expired %s ago)\n", expTime.Format(time.RFC3339), formatDuration(-jwt.ExpiresIn()))
		} else {
			yellow.Printf("Expires: %s (in %s)\n", expTime.Format(time.RFC3339), formatDuration(jwt.ExpiresIn()))
		}
	}

	if iat, ok := jwt.Payload["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		fmt.Printf("Issued At: %s\n", iatTime.Format(time.RFC3339))
	}

	if nbf, ok := jwt.Payload["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		fmt.Printf("Not Before: %s\n", nbfTime.Format(time.RFC3339))
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
}
