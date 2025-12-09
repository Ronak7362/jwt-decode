package decoder

import (
	"testing"
	"time"
)

func TestDecode_ValidToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	jwt, err := Decode(token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if jwt.Raw != token {
		t.Errorf("expected raw token to match input")
	}

	if len(jwt.Segments) != 3 {
		t.Errorf("expected 3 segments, got %d", len(jwt.Segments))
	}

	if alg, ok := jwt.Header["alg"].(string); !ok || alg != "HS256" {
		t.Errorf("expected alg=HS256, got %v", jwt.Header["alg"])
	}

	if sub, ok := jwt.Payload["sub"].(string); !ok || sub != "1234567890" {
		t.Errorf("expected sub=1234567890, got %v", jwt.Payload["sub"])
	}
}

func TestDecode_InvalidStructure(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"no segments", ""},
		{"one segment", "eyJhbGciOiJIUzI1NiJ9"},
		{"two segments", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0"},
		{"four segments", "a.b.c.d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.token)
			if err == nil {
				t.Error("expected error for invalid structure")
			}
		})
	}
}

func TestDecode_InvalidBase64(t *testing.T) {
	token := "invalid!!!.eyJzdWIiOiIxMjM0In0.sig"
	_, err := Decode(token)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDecode_InvalidJSON(t *testing.T) {
	token := "bm90anNvbg.bm90anNvbg.sig"
	_, err := Decode(token)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestIsExpired(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]interface{}
		expected bool
	}{
		{"expired", map[string]interface{}{"exp": float64(time.Now().Unix() - 3600)}, true},
		{"not expired", map[string]interface{}{"exp": float64(time.Now().Unix() + 3600)}, false},
		{"no exp claim", map[string]interface{}{"sub": "test"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwt := &JWT{Payload: tt.payload}
			if got := jwt.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExpiresIn(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour).Unix()
	jwt := &JWT{
		Payload: map[string]interface{}{"exp": float64(futureTime)},
	}

	duration := jwt.ExpiresIn()
	if duration < 59*time.Minute || duration > 61*time.Minute {
		t.Errorf("ExpiresIn() = %v, expected ~1 hour", duration)
	}
}

func TestExpiresIn_NoExpClaim(t *testing.T) {
	jwt := &JWT{Payload: map[string]interface{}{}}
	if duration := jwt.ExpiresIn(); duration != 0 {
		t.Errorf("ExpiresIn() = %v, want 0", duration)
	}
}

func TestPadBase64(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"YQ", "YQ=="},
		{"YWI", "YWI="},
		{"YWJj", "YWJj"},
		{"YWJjZA", "YWJjZA=="},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := padBase64(tt.input); got != tt.expected {
				t.Errorf("padBase64(%s) = %s, want %s", tt.input, got, tt.expected)
			}
		})
	}
}