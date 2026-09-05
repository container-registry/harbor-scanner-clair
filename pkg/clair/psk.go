package clair

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// jwtExpiry is how long a signed token stays valid. Quay uses 5m for the same
// call; 2m is enough for one request and its retries.
const jwtExpiry = 2 * time.Minute

// jwtNotBeforeSkew backdates nbf. Clair validates exp/nbf/iat with 15s of
// leeway and clairctl uses go-jose's 1-minute DefaultLeeway for exactly this
// reason: a clock a few seconds ahead of Clair's otherwise gets a 401.
const jwtNotBeforeSkew = 60 * time.Second

// signer mints the HS256 tokens Clair's PSK auth expects. Only signing is ever
// needed, with one algorithm and three claims, so there is no JWT dependency.
type signer struct {
	key    []byte
	issuer string
}

// newSigner decodes the base64 PSK. Clair stores auth.psk.key base64-encoded
// and decodes it before verifying, so the adapter must decode it before
// signing. A key that does not decode is a configuration error, not a runtime
// one: it is reported at construction so the process fails at startup.
func newSigner(psk, issuer string) (*signer, error) {
	key, err := base64.StdEncoding.DecodeString(psk)
	if err != nil {
		return nil, fmt.Errorf("decoding SCANNER_CLAIR_PSK as base64: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("SCANNER_CLAIR_PSK decodes to an empty key")
	}
	return &signer{key: key, issuer: issuer}, nil
}

func (s *signer) sign(now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshaling JWT header: %w", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": s.issuer,
		"iat": now.Unix(),
		"nbf": now.Add(-jwtNotBeforeSkew).Unix(),
		"exp": now.Add(jwtExpiry).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("marshaling JWT claims: %w", err)
	}

	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(signing))
	return signing + "." + enc.EncodeToString(mac.Sum(nil)), nil
}
