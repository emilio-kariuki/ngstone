package webhooktest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

func hmacHex(secret string, parts ...string) string {
	m := hmac.New(sha256.New, []byte(secret))
	for _, p := range parts {
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil))
}

func StripeSignature(secret string, timestamp int64, body []byte) string {
	ts := strconv.FormatInt(timestamp, 10)
	return "t=" + ts + ",v1=" + hmacHex(secret, ts, ".", string(body))
}

func GitHubSignature(secret string, body []byte) string {
	return "sha256=" + hmacHex(secret, string(body))
}

func SlackSignature(secret string, timestamp int64, body []byte) string {
	return "v0=" + hmacHex(secret, "v0:", strconv.FormatInt(timestamp, 10), ":", string(body))
}
