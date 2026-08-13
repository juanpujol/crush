package chatgpt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/stretchr/testify/require"
)

func TestDeviceAuthorization(t *testing.T) {
	t.Parallel()

	var polls atomic.Int64
	expiresAt := time.Now().Add(time.Hour).Unix()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/accounts/deviceauth/usercode":
			require.Equal(t, http.MethodPost, r.Method)
			requireJSONBody(t, r, map[string]string{"client_id": ClientID})
			writeJSON(t, w, map[string]string{
				"device_auth_id": "device-id",
				"usercode":       "ABCD-EFGH",
				"interval":       "0",
			})
		case "/api/accounts/deviceauth/token":
			requireJSONBody(t, r, map[string]string{
				"device_auth_id": "device-id",
				"user_code":      "ABCD-EFGH",
			})
			switch polls.Add(1) {
			case 1:
				w.WriteHeader(http.StatusForbidden)
			case 2:
				w.WriteHeader(http.StatusNotFound)
			default:
				writeJSON(t, w, map[string]string{
					"authorization_code": "authorization-code",
					"code_verifier":      "code-verifier",
					"code_challenge":     "qdgLLRr1saFHT6DWfWU28VNPIi7e9ynEBnBG3Oadw9g",
				})
			}
		case "/oauth/token":
			require.NoError(t, r.ParseForm())
			require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
			require.Equal(t, "authorization-code", r.Form.Get("code"))
			require.Equal(t, server.URL+"/deviceauth/callback", r.Form.Get("redirect_uri"))
			require.Equal(t, ClientID, r.Form.Get("client_id"))
			require.Equal(t, "code-verifier", r.Form.Get("code_verifier"))
			writeJSON(t, w, tokenResponse{
				IDToken:      fakeJWT(t, 0, "account-1", true),
				AccessToken:  fakeJWT(t, expiresAt, "", false),
				RefreshToken: "refresh-token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithIssuerURL(server.URL),
		WithPollTimeout(time.Second),
	)
	device, err := client.RequestDeviceCode(context.Background())
	require.NoError(t, err)
	require.Equal(t, "device-id", device.DeviceAuthID)
	require.Equal(t, "ABCD-EFGH", device.UserCode)
	require.Equal(t, server.URL+"/codex/device", device.VerificationURL)
	device.Interval = time.Millisecond

	authorization, err := client.PollAuthorization(context.Background(), device)
	require.NoError(t, err)
	auth, err := client.ExchangeAuthorization(context.Background(), authorization)
	require.NoError(t, err)
	require.Equal(t, "account-1", auth.AccountID)
	require.True(t, auth.FedRAMP)
	require.Equal(t, "refresh-token", auth.Token.RefreshToken)
	require.Equal(t, expiresAt, auth.Token.ExpiresAt)
	require.Equal(t, int64(3), polls.Load())
}

func TestPollAuthorizationRejectsMismatchedChallenge(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]string{
			"authorization_code": "authorization-code",
			"code_verifier":      "code-verifier",
			"code_challenge":     "wrong-challenge",
		})
	}))
	t.Cleanup(server.Close)

	client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
	_, err := client.PollAuthorization(context.Background(), DeviceCode{
		DeviceAuthID: "device-id",
		UserCode:     "code",
	})
	require.ErrorContains(t, err, "does not match challenge")
}

func TestRevokePrefersRefreshToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/oauth/revoke", r.URL.Path)
		requireJSONBody(t, r, map[string]string{
			"token":           "refresh-token",
			"token_type_hint": "refresh_token",
			"client_id":       ClientID,
		})
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
	require.NoError(t, client.Revoke(context.Background(), &oauth.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}))
}

func TestPollAuthorizationCancellationAndTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	device := DeviceCode{DeviceAuthID: "device-id", UserCode: "code", Interval: time.Second}

	t.Run("cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
		_, err := client.PollAuthorization(ctx, device)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()

		client := NewClient(
			WithHTTPClient(server.Client()),
			WithIssuerURL(server.URL),
			WithPollTimeout(time.Millisecond),
		)
		_, err := client.PollAuthorization(context.Background(), device)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestExchangeAuthorizationRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()

	tests := map[string]tokenResponse{
		"malformed access token": {
			IDToken:      fakeJWT(t, 0, "account-1", false),
			AccessToken:  "not-a-jwt",
			RefreshToken: "refresh-token",
		},
		"missing account ID": {
			IDToken:      fakeJWT(t, 0, "", false),
			AccessToken:  fakeJWT(t, time.Now().Add(time.Hour).Unix(), "", false),
			RefreshToken: "refresh-token",
		},
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, response)
			}))
			t.Cleanup(server.Close)

			client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
			_, err := client.ExchangeAuthorization(context.Background(), AuthorizationCode{
				AuthorizationCode: "authorization-code",
				CodeVerifier:      "code-verifier",
			})
			require.Error(t, err)
		})
	}
}

func TestRefreshMergesPartialResponseAndBindsAccount(t *testing.T) {
	t.Parallel()

	expiresAt := time.Now().Add(time.Hour).Unix()
	current := &oauth.Token{
		AccessToken:  fakeJWT(t, expiresAt, "", false),
		RefreshToken: "current-refresh-token",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireJSONBody(t, r, map[string]string{
			"client_id":     ClientID,
			"grant_type":    "refresh_token",
			"refresh_token": current.RefreshToken,
		})
		writeJSON(t, w, map[string]string{})
	}))
	t.Cleanup(server.Close)

	client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
	result, err := client.Refresh(context.Background(), current, "account-1")
	require.NoError(t, err)
	require.Equal(t, current.AccessToken, result.Token.AccessToken)
	require.Equal(t, current.RefreshToken, result.Token.RefreshToken)
	require.Equal(t, expiresAt, result.Token.ExpiresAt)
	require.Equal(t, "account-1", result.AccountID)
}

func TestRefreshRejectsAccountChange(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, tokenResponse{
			IDToken:      fakeJWT(t, 0, "account-2", false),
			AccessToken:  fakeJWT(t, time.Now().Add(time.Hour).Unix(), "", false),
			RefreshToken: "new-refresh-token",
		})
	}))
	t.Cleanup(server.Close)

	client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
	_, err := client.Refresh(context.Background(), &oauth.Token{
		AccessToken:  "old-access-token",
		RefreshToken: "old-refresh-token",
	}, "account-1")
	require.ErrorIs(t, err, ErrAccountMismatch)
	require.NotContains(t, err.Error(), "account-1")
	require.NotContains(t, err.Error(), "account-2")
}

func TestOAuthErrorsRedactCredentials(t *testing.T) {
	t.Parallel()

	const (
		authorizationCode = "sensitive-authorization-code"
		codeVerifier      = "sensitive-code-verifier"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(`{"message":"sensitive-authorization-code sensitive-code-verifier"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
	_, err := client.ExchangeAuthorization(context.Background(), AuthorizationCode{
		AuthorizationCode: authorizationCode,
		CodeVerifier:      codeVerifier,
	})
	require.Error(t, err)
	require.NotContains(t, err.Error(), authorizationCode)
	require.NotContains(t, err.Error(), codeVerifier)
	require.Contains(t, err.Error(), "unknown_error")
}

func TestRefreshFailureClassification(t *testing.T) {
	t.Parallel()

	for _, code := range []string{
		"refresh_token_expired",
		"refresh_token_reused",
		"refresh_token_invalidated",
	} {
		t.Run(code, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(t, w, map[string]string{"code": code})
			}))
			t.Cleanup(server.Close)

			client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
			_, err := client.Refresh(context.Background(), &oauth.Token{
				RefreshToken: "refresh-token",
			}, "account-1")
			var exchangeErr *oauth.TokenExchangeError
			require.ErrorAs(t, err, &exchangeErr)
			require.True(t, exchangeErr.IsRefreshTokenRevoked())
		})
	}
}

func fakeJWT(t *testing.T, expiresAt int64, accountID string, fedRAMP bool) string {
	t.Helper()
	claims := map[string]any{}
	if expiresAt != 0 {
		claims["exp"] = expiresAt
	}
	if accountID != "" || fedRAMP {
		claims["https://api.openai.com/auth"] = map[string]any{
			"chatgpt_account_id":         accountID,
			"chatgpt_account_is_fedramp": fedRAMP,
		}
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)),
		base64.RawURLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString([]byte("signature")),
	}, ".")
}

func requireJSONBody(t *testing.T, r *http.Request, expected map[string]string) {
	t.Helper()
	var actual map[string]string
	require.NoError(t, json.NewDecoder(r.Body).Decode(&actual))
	require.Equal(t, expected, actual)
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(value))
}

func TestParseJWTRequiresExactlyThreeSegments(t *testing.T) {
	t.Parallel()

	for _, token := range []string{"", "a.b", "a.b.c.d", ".b.c", "a..c", "a.b."} {
		t.Run(fmt.Sprintf("%q", token), func(t *testing.T) {
			t.Parallel()
			_, err := parseJWT(token)
			require.Error(t, err)
		})
	}
}

func TestRefreshTransientFailureIsNotRevoked(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(t, w, map[string]string{"code": "temporarily_unavailable"})
	}))
	t.Cleanup(server.Close)

	client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
	_, err := client.Refresh(context.Background(), &oauth.Token{
		RefreshToken: "refresh-token",
	}, "account-1")
	var exchangeErr *oauth.TokenExchangeError
	require.True(t, errors.As(err, &exchangeErr))
	require.False(t, exchangeErr.IsRefreshTokenRevoked())
}

func TestRefreshUnauthorizedClientIsNotRevoked(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(t, w, map[string]string{"code": "invalid_client"})
	}))
	t.Cleanup(server.Close)

	client := NewClient(WithHTTPClient(server.Client()), WithIssuerURL(server.URL))
	_, err := client.Refresh(context.Background(), &oauth.Token{
		RefreshToken: "refresh-token",
	}, "account-1")
	var exchangeErr *oauth.TokenExchangeError
	require.ErrorAs(t, err, &exchangeErr)
	require.False(t, exchangeErr.IsRefreshTokenRevoked())
}

func TestSanitizeErrorCode(t *testing.T) {
	t.Parallel()

	require.Equal(t, "refresh_token_expired", sanitizeErrorCode("refresh_token_expired"))
	require.Equal(t, "unknown_error", sanitizeErrorCode("credential: sensitive-value"))
	require.Equal(t, "unknown_error", sanitizeErrorCode(strings.Repeat("a", 65)))
}
