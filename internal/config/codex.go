package config

import (
	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
)

const codexBootstrapModelID = "gpt-5.3-codex"

// CodexProvider returns the catalog entry shown before authentication. The
// account-specific model catalog replaces this bootstrap model after login.
func CodexProvider() catwalk.Provider {
	return catwalk.Provider{
		ID:                  catwalk.InferenceProvider(chatgpt.ProviderID),
		Name:                chatgpt.ProviderName,
		Type:                catwalk.TypeOpenAI,
		APIEndpoint:         chatgpt.BackendURL,
		DefaultLargeModelID: codexBootstrapModelID,
		DefaultSmallModelID: codexBootstrapModelID,
		Models: []catwalk.Model{{
			ID:   codexBootstrapModelID,
			Name: "GPT-5.3 Codex",
		}},
	}
}

// NewCodexProviderConfig builds the complete provider configuration for a
// ChatGPT-backed Codex account.
func NewCodexProviderConfig(auth chatgpt.AuthResult) ProviderConfig {
	discoverModels := true
	headers := map[string]string{
		chatgpt.AccountIDHeader:  auth.AccountID,
		chatgpt.OriginatorHeader: chatgpt.Originator,
	}
	if auth.FedRAMP {
		headers[chatgpt.FedRAMPHeader] = "true"
	}

	return ProviderConfig{
		ID:                 chatgpt.ProviderID,
		Name:               chatgpt.ProviderName,
		BaseURL:            chatgpt.BackendURL,
		Type:               catwalk.TypeOpenAI,
		APIKey:             auth.Token.AccessToken,
		OAuthToken:         auth.Token,
		ExtraHeaders:       headers,
		FlatRate:           true,
		AutoDiscoverModels: &discoverModels,
	}
}
