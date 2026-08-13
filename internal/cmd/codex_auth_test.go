package cmd

import (
	"context"
	"testing"

	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
	"github.com/stretchr/testify/require"
)

type codexLoginStoreStub struct {
	config *config.Config
	calls  []configWrite
}

type configWrite struct {
	scope config.Scope
	key   string
	value any
}

func (s *codexLoginStoreStub) Config() *config.Config {
	return s.config
}

func (s *codexLoginStoreStub) SetConfigField(scope config.Scope, key string, value any) error {
	s.calls = append(s.calls, configWrite{scope: scope, key: key, value: value})
	return nil
}

func TestPersistCodexLoginReplacesCompleteProviderAtomically(t *testing.T) {
	t.Parallel()

	store := &codexLoginStoreStub{}
	auth := chatgpt.AuthResult{
		Token: &oauth.Token{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
		},
		AccountID: "new-account",
	}
	require.NoError(t, persistCodexLogin(store, auth))
	require.Len(t, store.calls, 1)
	require.Equal(t, config.ScopeGlobal, store.calls[0].scope)
	require.Equal(t, "providers.openai-codex", store.calls[0].key)

	provider, ok := store.calls[0].value.(config.ProviderConfig)
	require.True(t, ok)
	require.Equal(t, "new-account", provider.ExtraHeaders[chatgpt.AccountIDHeader])
	require.Equal(t, "new-access-token", provider.APIKey)
	require.Equal(t, "new-refresh-token", provider.OAuthToken.RefreshToken)
}

func TestLoginCodexSkipsExistingCredentialWithoutForce(t *testing.T) {
	t.Parallel()

	providers := csync.NewMap[string, config.ProviderConfig]()
	providers.Set(chatgpt.ProviderID, config.ProviderConfig{
		OAuthToken: &oauth.Token{AccessToken: "access-token"},
	})
	store := &codexLoginStoreStub{
		config: &config.Config{Providers: providers},
	}

	require.NoError(t, loginCodex(store, false))
	require.Empty(t, store.calls)
}

type configFieldRemoverStub struct {
	workspaceID string
	scope       config.Scope
	key         string
}

func (s *configFieldRemoverStub) RemoveConfigField(_ context.Context, workspaceID string, scope config.Scope, key string) error {
	s.workspaceID = workspaceID
	s.scope = scope
	s.key = key
	return nil
}

func TestLogoutCodexRemovesOnlyCodexProvider(t *testing.T) {
	t.Parallel()

	remover := &configFieldRemoverStub{}
	require.NoError(t, logoutCodexWithContext(context.Background(), remover, "workspace-1"))
	require.Equal(t, "workspace-1", remover.workspaceID)
	require.Equal(t, config.ScopeGlobal, remover.scope)
	require.Equal(t, "providers.openai-codex", remover.key)
}
