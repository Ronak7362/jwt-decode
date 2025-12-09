package decoder

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type JWT struct {
	Raw       string
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
	Segments  []string
}

func Decode(token string) (*JWT, error) {
	token = strings.TrimSpace(token)
	segments := strings.Split(token, ".")

	if len(segments) != 3 {
		return nil, fmt.Errorf("invalid JWT structure: expected 3 segments, got %d", len(segments))
	}

	header, err := decodeSegment(segments[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	payload, err := decodeSegment(segments[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	return &JWT{
		Raw:       token,
		Header:    header,
		Payload:   payload,
		Signature: segments[2],
		Segments:  segments,
	}, nil
}

func decodeSegment(segment string) (map[string]interface{}, error) {
	segment = padBase64(segment)
	data, err := base64.URLEncoding.DecodeString(segment)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}

func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

func (j *JWT) IsExpired() bool {
	exp, ok := j.Payload["exp"].(float64)
	if !ok {
		return false
	}
	return time.Now().Unix() > int64(exp)
}

func (j *JWT) ExpiresIn() time.Duration {
	exp, ok := j.Payload["exp"].(float64)
	if !ok {
		return 0
	}
	return time.Until(time.Unix(int64(exp), 0))
}
