package dialog

import (
	"context"
	"testing"

	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
	"github.com/stretchr/testify/require"
)

type codexOAuthClientStub struct {
	device        chatgpt.DeviceCode
	authorization chatgpt.AuthorizationCode
	auth          chatgpt.AuthResult
	pollStarted   chan struct{}
	waitForCancel bool
}

func (s *codexOAuthClientStub) RequestDeviceCode(context.Context) (chatgpt.DeviceCode, error) {
	return s.device, nil
}

func (s *codexOAuthClientStub) PollAuthorization(ctx context.Context, _ chatgpt.DeviceCode) (chatgpt.AuthorizationCode, error) {
	if s.pollStarted != nil {
		close(s.pollStarted)
	}
	if s.waitForCancel {
		<-ctx.Done()
		return chatgpt.AuthorizationCode{}, ctx.Err()
	}
	return s.authorization, nil
}

func (s *codexOAuthClientStub) ExchangeAuthorization(context.Context, chatgpt.AuthorizationCode) (chatgpt.AuthResult, error) {
	return s.auth, nil
}

func TestOAuthCodexSuccess(t *testing.T) {
	t.Parallel()

	token := &oauth.Token{AccessToken: "access-token", RefreshToken: "refresh-token"}
	client := &codexOAuthClientStub{
		device: chatgpt.DeviceCode{
			DeviceAuthID:    "device-id",
			UserCode:        "user-code",
			VerificationURL: "https://example.com/device",
		},
		authorization: chatgpt.AuthorizationCode{
			AuthorizationCode: "authorization-code",
			CodeVerifier:      "code-verifier",
		},
		auth: chatgpt.AuthResult{
			Token:     token,
			AccountID: "account-1",
		},
	}
	provider := &OAuthCodex{client: client, expectedAccountID: "account-1"}

	initiated, ok := provider.initiateAuth().(ActionInitiateOAuth)
	require.True(t, ok)
	require.Equal(t, "device-id", initiated.DeviceCode)
	require.Equal(t, "user-code", initiated.UserCode)

	completed, ok := provider.startPolling("", 0)().(ActionCompleteOAuth)
	require.True(t, ok)
	require.Equal(t, token, completed.Token)
	require.NoError(t, provider.validateCredential())
}

func TestOAuthCodexCancellation(t *testing.T) {
	t.Parallel()

	client := &codexOAuthClientStub{
		device:        chatgpt.DeviceCode{DeviceAuthID: "device-id"},
		pollStarted:   make(chan struct{}),
		waitForCancel: true,
	}
	provider := &OAuthCodex{client: client}
	result := make(chan any, 1)
	go func() {
		result <- provider.startPolling("", 0)()
	}()

	<-client.pollStarted
	require.Nil(t, provider.stopPolling())
	require.Nil(t, <-result)
}

func TestOAuthCodexRejectsDifferentAccount(t *testing.T) {
	t.Parallel()

	provider := &OAuthCodex{
		expectedAccountID: "account-1",
		authenticatedID:   "account-2",
	}
	require.ErrorIs(t, provider.validateCredential(), chatgpt.ErrAccountMismatch)
}
