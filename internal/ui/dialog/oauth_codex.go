package dialog

import (
	"context"
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
	"github.com/charmbracelet/crush/internal/ui/common"
)

func NewOAuthCodex(
	com *common.Common,
	isOnboarding bool,
	provider catwalk.Provider,
	model config.SelectedModel,
	modelType config.SelectedModelType,
	expectedAccountID string,
) (*OAuth, tea.Cmd) {
	return newOAuth(com, isOnboarding, provider, model, modelType, &OAuthCodex{
		client:            chatgpt.NewClient(),
		expectedAccountID: expectedAccountID,
	})
}

type OAuthCodex struct {
	client            codexOAuthClient
	device            chatgpt.DeviceCode
	expectedAccountID string
	authenticatedID   string
	auth              chatgpt.AuthResult
	cancelFunc        context.CancelFunc
}

type codexOAuthClient interface {
	RequestDeviceCode(ctx context.Context) (chatgpt.DeviceCode, error)
	PollAuthorization(ctx context.Context, device chatgpt.DeviceCode) (chatgpt.AuthorizationCode, error)
	ExchangeAuthorization(ctx context.Context, authorization chatgpt.AuthorizationCode) (chatgpt.AuthResult, error)
}

var (
	_ OAuthProvider            = (*OAuthCodex)(nil)
	_ oauthCredentialValidator = (*OAuthCodex)(nil)
	_ oauthCredentialSaver     = (*OAuthCodex)(nil)
)

func (m *OAuthCodex) name() string {
	return chatgpt.ProviderName
}

func (m *OAuthCodex) initiateAuth() tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	device, err := m.client.RequestDeviceCode(ctx)
	if err != nil {
		return ActionOAuthErrored{Error: fmt.Errorf("failed to initiate device auth: %w", err)}
	}
	m.device = device
	return ActionInitiateOAuth{
		DeviceCode:      device.DeviceAuthID,
		UserCode:        device.UserCode,
		ExpiresIn:       int((15 * time.Minute).Seconds()),
		VerificationURL: device.VerificationURL,
		Interval:        int(device.Interval.Seconds()),
	}
}

func (m *OAuthCodex) startPolling(_ string, _ int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithCancel(context.Background())
		m.cancelFunc = cancel

		authorization, err := m.client.PollAuthorization(ctx, m.device)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ActionOAuthErrored{Error: err}
		}
		auth, err := m.client.ExchangeAuthorization(ctx, authorization)
		if err != nil {
			return ActionOAuthErrored{Error: err}
		}
		m.authenticatedID = auth.AccountID
		m.auth = auth
		return ActionCompleteOAuth{Token: auth.Token}
	}
}

func (m *OAuthCodex) stopPolling() tea.Msg {
	if m.cancelFunc != nil {
		m.cancelFunc()
	}
	return nil
}

func (m *OAuthCodex) validateCredential() error {
	if m.expectedAccountID != "" && m.authenticatedID != m.expectedAccountID {
		return chatgpt.ErrAccountMismatch
	}
	return nil
}

func (m *OAuthCodex) saveCredential(com *common.Common, provider catwalk.Provider, token *oauth.Token) error {
	if m.expectedAccountID != "" {
		return com.Workspace.SetProviderAPIKey(config.ScopeGlobal, string(provider.ID), token)
	}
	return com.Workspace.SetConfigField(
		config.ScopeGlobal,
		"providers."+chatgpt.ProviderID,
		config.NewCodexProviderConfig(m.auth),
	)
}
