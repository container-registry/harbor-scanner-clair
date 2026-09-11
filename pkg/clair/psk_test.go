package clair

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPSK is the base64 form, the way it appears in Clair's auth.psk.key.
const testPSK = "RpnYFDQjNbD9zsj6iAByTNaI45Mnzzmr9FIrxiEAwi0="

func TestSignerProducesATokenClairAccepts(t *testing.T) {
	t.Parallel()

	s, err := newSigner(testPSK, "harbor-scanner-clair")
	require.NoError(t, err)

	now := time.Now()
	token, err := s.sign(now)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	// The signature is an HMAC-SHA256 over "<header>.<claims>" with the decoded
	// key, which is what Clair recomputes.
	key, err := base64.StdEncoding.DecodeString(testPSK)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	assert.Equal(t, expected, parts[2])

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	assert.JSONEq(t, `{"alg":"HS256","typ":"JWT"}`, string(header))

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Issuer    string `json:"iss"`
		IssuedAt  int64  `json:"iat"`
		NotBefore int64  `json:"nbf"`
		Expires   int64  `json:"exp"`
	}
	require.NoError(t, json.Unmarshal(rawClaims, &claims))

	assert.Equal(t, "harbor-scanner-clair", claims.Issuer)
	assert.Equal(t, now.Unix(), claims.IssuedAt)
	// nbf is backdated because Clair allows only 15s of leeway, so a clock a
	// few seconds ahead of Clair's would otherwise be rejected outright.
	assert.Equal(t, now.Add(-jwtNotBeforeSkew).Unix(), claims.NotBefore)
	assert.Equal(t, now.Add(jwtExpiry).Unix(), claims.Expires)
	assert.Less(t, claims.NotBefore, claims.IssuedAt)
	assert.Less(t, claims.IssuedAt, claims.Expires)
}

func TestSignerRejectsAKeyThatIsNotBase64(t *testing.T) {
	t.Parallel()

	_, err := newSigner("not base64!", "harbor-scanner-clair")
	require.Error(t, err)

	_, err = newSigner("", "harbor-scanner-clair")
	require.Error(t, err)
}

func TestClientAuthorizationHeader(t *testing.T) {
	t.Parallel()

	t.Run("sends a bearer token when a PSK is configured", func(t *testing.T) {
		t.Parallel()
		var authorization string
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			authorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNotFound)
		})
		s, err := newSigner(testPSK, "harbor-scanner-clair")
		require.NoError(t, err)
		c.signer = s

		_, err = c.MatcherReady(context.Background())
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(authorization, "Bearer "), "got %q", authorization)
		assert.Len(t, strings.Split(strings.TrimPrefix(authorization, "Bearer "), "."), 3)
	})

	// Clair returns the bare handler when auth.psk is nil, and an unexpected
	// Authorization header is not ignored by every proxy in front of it.
	t.Run("sends no Authorization header without a PSK", func(t *testing.T) {
		t.Parallel()
		var seen bool
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, seen = r.Header["Authorization"]
			w.WriteHeader(http.StatusNotFound)
		})

		_, err := c.MatcherReady(context.Background())
		require.NoError(t, err)
		assert.False(t, seen)
	})
}
