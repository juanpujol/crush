package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
	"github.com/stretchr/testify/require"
)

// newRefreshTestStore builds a ConfigStore whose selected provider holds an
// expired OAuth token, persisted both in memory and on disk at configPath.
// Stores that share a configPath also share the per-provider refresh lock,
// which lets a single test process faithfully simulate two crush instances:
// lock.File opens a fresh descriptor per call, so two stores block each
// other on the same lock file exactly as two processes would.
func newRefreshTestStore(t *testing.T, configPath, providerID string, exchange func(ctx context.Context, providerID string, provider ProviderConfig) (*oauth.Token, error)) *ConfigStore {
	t.Helper()

	expired := &oauth.Token{
		AccessToken:  "at0",
		RefreshToken: "rt0",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(-time.Hour).Unix(),
	}
	providerData := map[string]any{
		"id":              providerID,
		"name":            providerID,
		"type":            catwalk.TypeOpenAI,
		"base_url":        "https://example.com",
		"discover_models": false,
		"models": []catwalk.Model{{
			ID:   "test-model",
			Name: "Test Model",
		}},
		"api_key": expired.AccessToken,
		"oauth":   expired,
	}
	extraHeaders := map[string]string(nil)
	if providerID == chatgpt.ProviderID {
		extraHeaders = map[string]string{chatgpt.AccountIDHeader: "account-1"}
		providerData["extra_headers"] = extraHeaders
	}
	configContent, err := json.Marshal(map[string]any{
		"providers": map[string]any{
			providerID: providerData,
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, configContent, 0o600))

	providers := csync.NewMap[string, ProviderConfig]()
	providers.Set(providerID, ProviderConfig{
		ID:           providerID,
		Name:         providerID,
		APIKey:       expired.AccessToken,
		OAuthToken:   expired,
		ExtraHeaders: extraHeaders,
		Models: []catwalk.Model{{
			ID:   "test-model",
			Name: "Test Model",
		}},
	})

	return &ConfigStore{
		config:         &Config{Providers: providers},
		globalDataPath: configPath,
		workingDir:     filepath.Dir(configPath),
		exchangeToken:  exchange,
	}
}

func writeTokenToDisk(t *testing.T, path string, token *oauth.Token) {
	t.Helper()
	configContent, err := json.Marshal(map[string]any{
		"providers": map[string]any{
			"hyper": map[string]any{
				"api_key": token.AccessToken,
				"oauth":   token,
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, configContent, 0o600))
}

func writeCodexAuthToDisk(t *testing.T, path string, token *oauth.Token, accountID string) {
	t.Helper()
	configContent, err := json.Marshal(map[string]any{
		"providers": map[string]any{
			chatgpt.ProviderID: map[string]any{
				"api_key": token.AccessToken,
				"oauth":   token,
				"extra_headers": map[string]string{
					chatgpt.AccountIDHeader: accountID,
				},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, configContent, 0o600))
}

// TestRefreshOAuthToken_InProcessSingleFlight verifies that a storm of
// concurrent refresh calls for the same provider collapses into a single
// token exchange.
func TestRefreshOAuthToken_InProcessSingleFlight(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "crush.json")

	var exchanges atomic.Int64
	store := newRefreshTestStore(t, configPath, "hyper", func(ctx context.Context, providerID string, provider ProviderConfig) (*oauth.Token, error) {
		exchanges.Add(1)
		time.Sleep(50 * time.Millisecond) // hold the flight open so peers join
		return &oauth.Token{
			AccessToken:  "at1",
			RefreshToken: "rt1",
			ExpiresIn:    3600,
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		}, nil
	})

	const goroutines = 20
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, goroutines)
	for range goroutines {
		wg.Go(func() {
			<-start
			errs <- store.RefreshOAuthToken(context.Background(), ScopeGlobal, "hyper")
		})
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int64(1), exchanges.Load(), "concurrent refreshes should collapse into one exchange")

	pc, ok := store.config.Providers.Get("hyper")
	require.True(t, ok)
	require.Equal(t, "at1", pc.OAuthToken.AccessToken)
	require.Equal(t, "rt1", pc.OAuthToken.RefreshToken)
}

// TestRefreshOAuthToken_CrossProcessAdopt verifies that when two instances
// share a credential, only one performs the token exchange and the other
// adopts the rotated token from disk rather than reusing the consumed
// refresh token. The fake exchange models a rotating provider: reusing a
// refresh token it has already rotated returns an error, so a second
// exchange would be observable as a failure.
func TestRefreshOAuthToken_CrossProcessAdopt(t *testing.T) {
	t.Parallel()

	for _, providerID := range []string{"hyper", chatgpt.ProviderID} {
		t.Run(providerID, func(t *testing.T) {
			t.Parallel()

			configPath := filepath.Join(t.TempDir(), "crush.json")
			var (
				mu          sync.Mutex
				current     = "rt0"
				exchanges   atomic.Int64
				reuseErrors atomic.Int64
			)
			exchange := func(ctx context.Context, providerID string, provider ProviderConfig) (*oauth.Token, error) {
				mu.Lock()
				defer mu.Unlock()
				refreshToken := provider.OAuthToken.RefreshToken
				if refreshToken != current {
					reuseErrors.Add(1)
					return nil, fmt.Errorf("refresh token revoked")
				}
				exchanges.Add(1)
				time.Sleep(50 * time.Millisecond)
				current = "rt1"
				return &oauth.Token{
					AccessToken:  "at1",
					RefreshToken: "rt1",
					ExpiresIn:    3600,
					ExpiresAt:    time.Now().Add(time.Hour).Unix(),
				}, nil
			}

			a := newRefreshTestStore(t, configPath, providerID, exchange)
			b := newRefreshTestStore(t, configPath, providerID, exchange)

			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make(chan error, 2)
			for _, store := range []*ConfigStore{a, b} {
				wg.Go(func() {
					<-start
					errs <- store.RefreshOAuthToken(context.Background(), ScopeGlobal, providerID)
				})
			}
			close(start)
			wg.Wait()
			close(errs)

			for err := range errs {
				require.NoError(t, err)
			}
			require.Equal(t, int64(1), exchanges.Load(), "only one instance should exchange")
			require.Equal(t, int64(0), reuseErrors.Load(), "no instance should reuse a rotated refresh token")

			for name, store := range map[string]*ConfigStore{"a": a, "b": b} {
				provider, ok := store.config.Providers.Get(providerID)
				require.True(t, ok, name)
				require.Equal(t, "at1", provider.OAuthToken.AccessToken, name)
				require.Equal(t, "rt1", provider.OAuthToken.RefreshToken, name)
			}
		})
	}
}

// rotatingExchange models a provider that rotates refresh tokens and
// revokes the previous one: presenting anything other than the currently
// live refresh token fails the way a real reuse-detecting server would.
// Tokens are handed out as at<n>/rt<n> starting at next. The returned
// counters report successful exchanges and reuse attempts.
func rotatingExchange(live string, next int) (exchange func(ctx context.Context, providerID string, provider ProviderConfig) (*oauth.Token, error), exchanges, reuse *atomic.Int64) {
	var (
		mu        sync.Mutex
		exchanged atomic.Int64
		reused    atomic.Int64
	)
	return func(ctx context.Context, providerID string, provider ProviderConfig) (*oauth.Token, error) {
		mu.Lock()
		defer mu.Unlock()
		refreshToken := provider.OAuthToken.RefreshToken
		if refreshToken != live {
			reused.Add(1)
			return nil, &oauth.TokenExchangeError{StatusCode: 400, Body: `{"error":"invalid_grant"}`}
		}
		exchanged.Add(1)
		token := &oauth.Token{
			AccessToken:  fmt.Sprintf("at%d", next),
			RefreshToken: fmt.Sprintf("rt%d", next),
			ExpiresIn:    3600,
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		}
		live = token.RefreshToken
		next++
		return token, nil
	}, &exchanged, &reused
}

// TestRefreshOAuthToken_StalePeerBorrowsRotatedRefreshToken covers the
// instance that has been idle while a peer rotated the credential several
// times. Its own refresh token is long dead, and the token on disk has
// itself aged out, so there is nothing to adopt outright. The stale
// instance must still recover by exchanging with the refresh token from
// disk rather than presenting its own revoked one, which would revoke the
// whole token family and force the user to log in again.
func TestRefreshOAuthToken_StalePeerBorrowsRotatedRefreshToken(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "crush.json")
	exchange, exchanges, reuse := rotatingExchange("rt3", 4)
	store := newRefreshTestStore(t, configPath, "hyper", exchange)

	// Disk holds the peer's third rotation, whose access token has also
	// expired. In memory we are still back on the original credential.
	writeTokenToDisk(t, configPath, &oauth.Token{
		AccessToken:  "at3",
		RefreshToken: "rt3",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(-time.Minute).Unix(),
	})

	require.NoError(t, store.RefreshOAuthToken(context.Background(), ScopeGlobal, "hyper"))
	require.Equal(t, int64(1), exchanges.Load())
	require.Equal(t, int64(0), reuse.Load(), "must not present its own revoked refresh token")

	pc, ok := store.config.Providers.Get("hyper")
	require.True(t, ok)
	require.Equal(t, "at4", pc.OAuthToken.AccessToken)
	require.Equal(t, "rt4", pc.OAuthToken.RefreshToken)
	require.Equal(t, "at4", pc.APIKey)
}

// TestRefreshOAuthToken_AdoptsFresherDiskToken verifies that an instance
// whose in-memory credential has aged out adopts a peer's still-valid
// token from disk without spending an exchange at all.
func TestRefreshOAuthToken_AdoptsFresherDiskToken(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "crush.json")
	exchange, exchanges, _ := rotatingExchange("rt9", 10)
	store := newRefreshTestStore(t, configPath, "hyper", exchange)

	writeTokenToDisk(t, configPath, &oauth.Token{
		AccessToken:  "at9",
		RefreshToken: "rt9",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})

	require.NoError(t, store.RefreshOAuthToken(context.Background(), ScopeGlobal, "hyper"))
	require.Equal(t, int64(0), exchanges.Load(), "a usable peer token needs no exchange")

	pc, ok := store.config.Providers.Get("hyper")
	require.True(t, ok)
	require.Equal(t, "at9", pc.OAuthToken.AccessToken)
	require.Equal(t, "at9", pc.APIKey)
}

func TestRefreshOAuthToken_AdoptsCodexAccountMetadata(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "crush.json")
	store := newRefreshTestStore(t, configPath, chatgpt.ProviderID, func(context.Context, string, ProviderConfig) (*oauth.Token, error) {
		return nil, fmt.Errorf("exchange should not run")
	})
	provider, ok := store.config.Providers.Get(chatgpt.ProviderID)
	require.True(t, ok)
	provider.ExtraHeaders = map[string]string{chatgpt.AccountIDHeader: "account-old"}
	store.config.Providers.Set(chatgpt.ProviderID, provider)

	diskToken := &oauth.Token{
		AccessToken:  "at-new",
		RefreshToken: "rt-new",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	}
	writeCodexAuthToDisk(t, configPath, diskToken, "account-new")

	require.NoError(t, store.RefreshOAuthToken(context.Background(), ScopeGlobal, chatgpt.ProviderID))
	adopted, ok := store.config.Providers.Get(chatgpt.ProviderID)
	require.True(t, ok)
	require.Equal(t, "at-new", adopted.APIKey)
	require.Equal(t, "account-new", adopted.ExtraHeaders[chatgpt.AccountIDHeader])
}

func TestSyncDiskAuthRejectsDifferentTokenSnapshot(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "crush.json")
	store := newRefreshTestStore(t, configPath, chatgpt.ProviderID, nil)
	writeCodexAuthToDisk(t, configPath, &oauth.Token{
		AccessToken:  "at-newer",
		RefreshToken: "rt-newer",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	}, "account-newer")

	provider := ProviderConfig{ExtraHeaders: map[string]string{
		chatgpt.AccountIDHeader: "account-old",
		"X-Custom":              "resolved-value",
	}}
	err := store.syncDiskAuth(ScopeGlobal, chatgpt.ProviderID, &oauth.Token{
		AccessToken:  "at-expected",
		RefreshToken: "rt-expected",
	}, &provider)
	require.ErrorContains(t, err, "credentials changed")
	require.Equal(t, "account-old", provider.ExtraHeaders[chatgpt.AccountIDHeader])
	require.Equal(t, "resolved-value", provider.ExtraHeaders["X-Custom"])
}

// TestRefreshOAuthToken_IgnoresOlderDiskToken guards against walking
// backwards: a config file holding an older credential than the one we
// already have must not be adopted or borrowed from.
func TestRefreshOAuthToken_IgnoresOlderDiskToken(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "crush.json")
	exchange, exchanges, reuse := rotatingExchange("rt0", 1)
	store := newRefreshTestStore(t, configPath, "hyper", exchange)

	writeTokenToDisk(t, configPath, &oauth.Token{
		AccessToken:  "ancient",
		RefreshToken: "ancient-rt",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(-24 * time.Hour).Unix(),
	})

	require.NoError(t, store.RefreshOAuthToken(context.Background(), ScopeGlobal, "hyper"))
	require.Equal(t, int64(1), exchanges.Load())
	require.Equal(t, int64(0), reuse.Load())

	pc, ok := store.config.Providers.Get("hyper")
	require.True(t, ok)
	require.Equal(t, "rt1", pc.OAuthToken.RefreshToken)
}

func TestRefreshOAuthToken_AdoptsRefreshTokenOnlyRotation(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "crush.json")
	exchange, exchanges, reuse := rotatingExchange("rt1", 2)
	store := newRefreshTestStore(t, configPath, "hyper", exchange)

	writeTokenToDisk(t, configPath, &oauth.Token{
		AccessToken:  "at0",
		RefreshToken: "rt1",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(-time.Minute).Unix(),
	})

	require.NoError(t, store.RefreshOAuthToken(context.Background(), ScopeGlobal, "hyper"))
	require.Equal(t, int64(1), exchanges.Load())
	require.Equal(t, int64(0), reuse.Load())

	provider, ok := store.Config().Providers.Get("hyper")
	require.True(t, ok)
	require.Equal(t, "at2", provider.OAuthToken.AccessToken)
	require.Equal(t, "rt2", provider.OAuthToken.RefreshToken)
}

func TestRefreshOAuthToken_DoesNotPublishUnpersistedToken(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "crush.json")
	store := newRefreshTestStore(t, configPath, "hyper", func(context.Context, string, ProviderConfig) (*oauth.Token, error) {
		return &oauth.Token{
			AccessToken:  "at1",
			RefreshToken: "rt1",
			ExpiresIn:    3600,
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		}, nil
	})
	store.globalDataPath = t.TempDir()

	require.ErrorContains(t, store.RefreshOAuthToken(context.Background(), ScopeGlobal, "hyper"), "persist refreshed token")

	provider, ok := store.Config().Providers.Get("hyper")
	require.True(t, ok)
	require.Equal(t, "at0", provider.OAuthToken.AccessToken)
	require.Equal(t, "rt0", provider.OAuthToken.RefreshToken)
}

func TestRefreshOAuthToken_LogoutDoesNotRestoreCredentials(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "crush.json")
	exchangeStarted := make(chan struct{})
	releaseExchange := make(chan struct{})
	store := newRefreshTestStore(t, configPath, chatgpt.ProviderID, func(context.Context, string, ProviderConfig) (*oauth.Token, error) {
		close(exchangeStarted)
		<-releaseExchange
		return &oauth.Token{
			AccessToken:  "at1",
			RefreshToken: "rt1",
			ExpiresIn:    3600,
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		}, nil
	})

	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- store.RefreshOAuthToken(context.Background(), ScopeGlobal, chatgpt.ProviderID)
	}()
	<-exchangeStarted

	logoutDone := make(chan error, 1)
	go func() {
		logoutDone <- store.RemoveConfigField(ScopeGlobal, "providers."+chatgpt.ProviderID)
	}()
	var (
		logoutErr       error
		logoutCompleted bool
	)
	select {
	case logoutErr = <-logoutDone:
		logoutCompleted = true
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseExchange)
	require.NoError(t, <-refreshDone)
	if !logoutCompleted {
		logoutErr = <-logoutDone
	}
	require.NoError(t, logoutErr)

	require.False(t, store.HasConfigField(ScopeGlobal, "providers."+chatgpt.ProviderID))
	_, exists := store.Config().Providers.Get(chatgpt.ProviderID)
	require.False(t, exists)
}

func TestWithRefreshLock_DoesNotWriteWithoutLock(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	blocked := filepath.Join(parent, "blocked")
	require.NoError(t, os.WriteFile(blocked, []byte("not a directory"), 0o600))
	store := &ConfigStore{globalDataPath: filepath.Join(blocked, "crush.json")}
	wrote := false

	require.Error(t, store.withRefreshLock(chatgpt.ProviderID, func() error {
		wrote = true
		return nil
	}))
	require.False(t, wrote)
}
