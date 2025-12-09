package formatter

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/user/jwt-decode/decoder"
)

func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrint_BasicOutput(t *testing.T) {
	jwt := &decoder.JWT{
		Header:  map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		Payload: map[string]interface{}{"sub": "1234567890", "name": "John Doe"},
		Segments: []string{"header", "payload", "signature"},
	}

	output := captureOutput(func() {
		Print(jwt, false, false)
	})

	if !strings.Contains(output, "JWT Token Decoded Successfully") {
		t.Error("expected success message")
	}
	if !strings.Contains(output, "Header:") {
		t.Error("expected Header section")
	}
	if !strings.Contains(output, "Payload:") {
		t.Error("expected Payload section")
	}
	if !strings.Contains(output, "HS256") {
		t.Error("expected algorithm in output")
	}
}

func TestPrint_WithRawSegments(t *testing.T) {
	jwt := &decoder.JWT{
		Header:  map[string]interface{}{"alg": "HS256"},
		Payload: map[string]interface{}{"sub": "test"},
		Segments: []string{"seg1", "seg2", "seg3"},
	}

	output := captureOutput(func() {
		Print(jwt, false, true)
	})

	if !strings.Contains(output, "Raw Segments:") {
		t.Error("expected Raw Segments section")
	}
	if !strings.Contains(output, "seg1") || !strings.Contains(output, "seg2") {
		t.Error("expected segment values in output")
	}
}

func TestPrint_ExpiredToken(t *testing.T) {
	expiredTime := time.Now().Add(-1 * time.Hour).Unix()
	jwt := &decoder.JWT{
		Header:  map[string]interface{}{"alg": "HS256"},
		Payload: map[string]interface{}{"exp": float64(expiredTime)},
	}

	output := captureOutput(func() {
		Print(jwt, false, false)
	})

	if !strings.Contains(output, "Expired") {
		t.Error("expected Expired warning")
	}
}

func TestPrint_NotExpiredToken(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour).Unix()
	jwt := &decoder.JWT{
		Header:  map[string]interface{}{"alg": "HS256"},
		Payload: map[string]interface{}{"exp": float64(futureTime)},
	}

	output := captureOutput(func() {
		Print(jwt, false, false)
	})

	if !strings.Contains(output, "Expires:") {
		t.Error("expected Expires message")
	}
	if strings.Contains(output, "Expired") {
		t.Error("should not show Expired for future token")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		contains string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m"},
		{3600 * time.Second, "1h"},
		{25 * time.Hour, "1d"},
	}

	for _, tt := range tests {
		t.Run(tt.contains, func(t *testing.T) {
			result := formatDuration(tt.duration)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("formatDuration(%v) = %s, expected to contain %s", tt.duration, result, tt.contains)
			}
		})
	}
}