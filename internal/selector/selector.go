package selector

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var varPattern = regexp.MustCompile(`\$\{(\w+)(:[0-9]+)?\}`)

type Builder struct {
	Format string
	Now    func() time.Time
	Random io.Reader
}

func (b Builder) Parse() (string, error) {
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	if strings.TrimSpace(b.Format) == "" {
		return "", fmt.Errorf("selector format is empty")
	}

	random := b.Random
	if random == nil {
		random = rand.Reader
	}
	var replaceErr error
	out := varPattern.ReplaceAllStringFunc(b.Format, func(m string) string {
		parts := varPattern.FindStringSubmatch(m)
		if len(parts) < 2 {
			return m
		}
		key := strings.ToLower(parts[1])
		length := 0
		if len(parts) > 2 && parts[2] != "" {
			parsed, err := strconv.Atoi(strings.TrimPrefix(parts[2], ":"))
			if err == nil {
				length = parsed
			}
		}

		switch key {
		case "randomhex":
			if length <= 0 || length > 64 {
				return ""
			}
			seed := make([]byte, 128)
			if _, err := io.ReadFull(random, seed); err != nil {
				replaceErr = fmt.Errorf("read selector randomness: %w", err)
				return ""
			}
			h := sha256.Sum256(seed)
			return strings.ToUpper(hex.EncodeToString(h[:])[:length])
		case "year":
			return fmt.Sprintf("%04d", now().Year())
		case "month":
			return fmt.Sprintf("%02d", int(now().Month()))
		case "day":
			return fmt.Sprintf("%02d", now().Day())
		default:
			return ""
		}
	})
	if replaceErr != nil {
		return "", replaceErr
	}

	if strings.Contains(out, "${") || strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("invalid selector format")
	}
	return out, nil
}

func ValidateRecordName(selectorName, domainName string) error {
	record := selectorName + "._domainkey." + domainName
	labels := strings.Split(record, ".")
	total := 0
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("label %q too long: %d > 63", label, len(label))
		}
		total += len(label)
	}
	total += len(labels) - 1
	if total > 253 {
		return fmt.Errorf("record too long: %d > 253", total)
	}
	return nil
}
