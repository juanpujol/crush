package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/env"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
	"github.com/stretchr/testify/require"
)

func TestConfigureCodexProvider(t *testing.T) {
	t.Run("discovery removes bootstrap and preserves configured models", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "/models", r.URL.Path)
			_, _ = w.Write([]byte(`{"models":[{"slug":"discovered-model","display_name":"Discovered","visibility":"list"}]}`))
		}))
		defer server.Close()

		discoverTrue := true
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				chatgpt.ProviderID: {
					ID:                 chatgpt.ProviderID,
					APIKey:             "access-token",
					BaseURL:            server.URL,
					AutoDiscoverModels: &discoverTrue,
					Models: []catwalk.Model{
						{ID: "custom-model", Name: "Custom", ContextWindow: 12345},
					},
				},
			}),
		}
		cfg.setDefaults("/tmp", "")

		testEnv := env.NewFromMap(map[string]string{})
		resolver := NewShellVariableResolver(testEnv)
		err := cfg.configureProviders(context.Background(), testStore(cfg), testEnv, resolver, []catwalk.Provider{CodexProvider()})
		require.NoError(t, err)

		provider, exists := cfg.Providers.Get(chatgpt.ProviderID)
		require.True(t, exists)
		require.Len(t, provider.Models, 2)
		require.Equal(t, "custom-model", provider.Models[0].ID)
		require.Equal(t, int64(12345), provider.Models[0].ContextWindow)
		require.Equal(t, "discovered-model", provider.Models[1].ID)
	})

	t.Run("discovery preserves explicitly configured bootstrap model", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"models":[{"slug":"discovered-model","display_name":"Discovered","visibility":"list"}]}`))
		}))
		defer server.Close()

		discoverTrue := true
		explicit := CodexProvider().Models[0]
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				chatgpt.ProviderID: {
					APIKey:             "access-token",
					BaseURL:            server.URL,
					AutoDiscoverModels: &discoverTrue,
					Models:             []catwalk.Model{explicit},
				},
			}),
		}
		cfg.setDefaults("/tmp", "")
		testEnv := env.NewFromMap(map[string]string{})
		err := cfg.configureProviders(
			context.Background(),
			testStore(cfg),
			testEnv,
			NewShellVariableResolver(testEnv),
			[]catwalk.Provider{CodexProvider()},
		)
		require.NoError(t, err)

		provider, exists := cfg.Providers.Get(chatgpt.ProviderID)
		require.True(t, exists)
		require.Len(t, provider.Models, 2)
		require.Equal(t, explicit, provider.Models[0])
		require.Equal(t, "discovered-model", provider.Models[1].ID)
		require.Equal(t, "Discovered", provider.Models[1].Name)
	})

	t.Run("credentials cannot be redirected by workspace config", func(t *testing.T) {
		var authorization string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorization = r.Header.Get("Authorization")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}))
		defer server.Close()

		global := []byte(`{"providers":{"openai-codex":{"api_key":"global-secret","oauth":{"access_token":"global-secret","refresh_token":"refresh-token"},"discover_models":true}}}`)
		workspace := []byte(`{"providers":{"openai-codex":{"base_url":"` + server.URL + `"}}}`)
		cfg, err := loadFromBytes([][]byte{global, workspace})
		require.NoError(t, err)
		cfg.setDefaults(t.TempDir(), "")
		testEnv := env.NewFromMap(map[string]string{})

		require.NoError(t, cfg.configureProviders(
			context.Background(),
			testStore(cfg),
			testEnv,
			NewShellVariableResolver(testEnv),
			[]catwalk.Provider{CodexProvider()},
		))
		require.Empty(t, authorization)
	})

	t.Run("discovery authentication failure preserves selected model", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}))
		defer server.Close()

		discoverTrue := true
		cfg := &Config{
			Models: map[SelectedModelType]SelectedModel{
				SelectedModelTypeLarge: {Provider: chatgpt.ProviderID, Model: "account-model"},
			},
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				chatgpt.ProviderID: {
					APIKey:             "expired-access-token",
					BaseURL:            server.URL,
					AutoDiscoverModels: &discoverTrue,
				},
			}),
		}
		cfg.setDefaults(t.TempDir(), "")
		testEnv := env.NewFromMap(map[string]string{})

		require.NoError(t, cfg.configureProviders(
			context.Background(),
			testStore(cfg),
			testEnv,
			NewShellVariableResolver(testEnv),
			[]catwalk.Provider{CodexProvider()},
		))
		resolved, err := resolveSelectedModels(cfg, []catwalk.Provider{CodexProvider()})
		require.NoError(t, err)
		require.False(t, resolved.LargeFallback)
		require.Equal(t, "account-model", resolved.Large.Model)
	})
}
