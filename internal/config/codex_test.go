package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
	"github.com/stretchr/testify/require"
)

func TestNewCodexProviderConfig(t *testing.T) {
	t.Parallel()

	token := &oauth.Token{AccessToken: "access-token", RefreshToken: "refresh-token"}
	provider := NewCodexProviderConfig(chatgpt.AuthResult{
		Token:     token,
		AccountID: "account-1",
		FedRAMP:   true,
	})
	require.Equal(t, chatgpt.ProviderID, provider.ID)
	require.Equal(t, chatgpt.ProviderName, provider.Name)
	require.Equal(t, chatgpt.BackendURL, provider.BaseURL)
	require.Equal(t, catwalk.TypeOpenAI, provider.Type)
	require.Equal(t, token, provider.OAuthToken)
	require.Equal(t, token.AccessToken, provider.APIKey)
	require.Equal(t, "account-1", provider.ExtraHeaders[chatgpt.AccountIDHeader])
	require.Equal(t, chatgpt.Originator, provider.ExtraHeaders[chatgpt.OriginatorHeader])
	require.Equal(t, "true", provider.ExtraHeaders[chatgpt.FedRAMPHeader])
	require.True(t, provider.FlatRate)
	require.NotNil(t, provider.AutoDiscoverModels)
	require.True(t, *provider.AutoDiscoverModels)
}

func TestNewCodexProviderConfigOmitsFedRAMPHeader(t *testing.T) {
	t.Parallel()

	provider := NewCodexProviderConfig(chatgpt.AuthResult{
		Token:     &oauth.Token{AccessToken: "access-token"},
		AccountID: "account-1",
	})
	require.NotContains(t, provider.ExtraHeaders, chatgpt.FedRAMPHeader)
}

func TestCodexProviderPersistencePreservesOpenAI(t *testing.T) {
	t.Setenv("CRUSH_DISABLE_PROVIDER_AUTO_UPDATE", "1")

	configPath := filepath.Join(t.TempDir(), "crush.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
		"providers": {
			"openai": {
				"api_key": "openai-key"
			}
		}
	}`), 0o644))

	providers := csync.NewMap[string, ProviderConfig]()
	store := &ConfigStore{
		config:         &Config{Providers: providers},
		globalDataPath: configPath,
		workingDir:     filepath.Dir(configPath),
	}
	codex := NewCodexProviderConfig(chatgpt.AuthResult{
		Token: &oauth.Token{
			AccessToken:  "codex-access-token",
			RefreshToken: "codex-refresh-token",
		},
		AccountID: "account-1",
	})
	discoverModels := false
	codex.AutoDiscoverModels = &discoverModels
	codex.Models = []catwalk.Model{{ID: "gpt-5-codex", Name: "GPT-5 Codex"}}

	require.NoError(t, store.SetConfigField(ScopeGlobal, "providers.openai-codex", codex))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(configPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.Equal(t, "openai-key", jsonPathString(t, data, "providers", "openai", "api_key"))
	require.Equal(t, "codex-access-token", jsonPathString(t, data, "providers", "openai-codex", "api_key"))

	require.NoError(t, store.RemoveConfigField(ScopeGlobal, "providers.openai-codex"))
	data, err = os.ReadFile(configPath)
	require.NoError(t, err)
	require.Equal(t, "openai-key", jsonPathString(t, data, "providers", "openai", "api_key"))
	var root map[string]any
	require.NoError(t, json.Unmarshal(data, &root))
	persistedProviders, ok := root["providers"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, persistedProviders, "openai-codex")
}

func TestCodexProviderPersistenceSignalsAuthComplete(t *testing.T) {
	t.Parallel()

	store := &ConfigStore{
		config:         &Config{Providers: csync.NewMap[string, ProviderConfig]()},
		globalDataPath: filepath.Join(t.TempDir(), "crush.json"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waited := make(chan error, 1)
	go func() {
		waited <- store.WaitForTokenChange(ctx, chatgpt.ProviderID)
	}()

	require.NoError(t, store.SetConfigField(ScopeGlobal, "providers."+chatgpt.ProviderID, ProviderConfig{}))
	require.NoError(t, <-waited)
}

func jsonPathString(t *testing.T, data []byte, path ...string) string {
	t.Helper()
	var value any
	require.NoError(t, json.Unmarshal(data, &value))
	for _, component := range path {
		object, ok := value.(map[string]any)
		require.True(t, ok)
		value = object[component]
	}
	result, ok := value.(string)
	require.True(t, ok)
	return result
}
