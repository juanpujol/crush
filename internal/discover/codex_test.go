package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
	"github.com/stretchr/testify/require"
)

func TestDiscoverCodexModels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/models", r.URL.Path)
		require.Equal(t, CodexCompatibilityVersion, r.URL.Query().Get("client_version"))
		require.Equal(t, "Bearer access-token", r.Header.Get("Authorization"))
		require.Equal(t, "account-1", r.Header.Get(chatgpt.AccountIDHeader))
		require.Equal(t, chatgpt.Originator, r.Header.Get(chatgpt.OriginatorHeader))
		require.Equal(t, "true", r.Header.Get(chatgpt.FedRAMPHeader))
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{
			"models": [
				{
					"slug": "hidden",
					"display_name": "Hidden",
					"visibility": "hide",
					"priority": 0
				},
				{
					"slug": "reasoning",
					"display_name": "Reasoning",
					"default_reasoning_level": "max",
					"supported_reasoning_levels": [
						{"effort": "xhigh"},
						{"effort": "max"},
						{"effort": "ultra"}
					],
					"visibility": "list",
					"priority": 20,
					"context_window": 200000,
					"input_modalities": ["text", "image"]
				},
				{
					"slug": "stable-first",
					"display_name": "Stable First",
					"visibility": "list",
					"priority": 10,
					"input_modalities": ["text"]
				},
				{
					"slug": "stable-second",
					"display_name": "Stable Second",
					"visibility": "list",
					"priority": 10,
					"input_modalities": ["text"]
				}
			]
		}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	explicit := catwalk.Model{
		ID:            "reasoning",
		Name:          "Custom Reasoning",
		ContextWindow: 400000,
	}
	models, err := DiscoverModels(context.Background(), Config{
		ID:      chatgpt.ProviderID,
		BaseURL: server.URL,
		APIKey:  "access-token",
		ExtraHeaders: map[string]string{
			chatgpt.AccountIDHeader:  "account-1",
			chatgpt.OriginatorHeader: chatgpt.Originator,
			chatgpt.FedRAMPHeader:    "true",
		},
		ExistingModels: []catwalk.Model{explicit},
	}, &mockResolver{})
	require.NoError(t, err)
	require.Equal(t, []string{"reasoning", "stable-first", "stable-second"}, modelIDs(models))
	require.Equal(t, explicit, models[0])
	require.False(t, models[1].SupportsImages)
	require.Zero(t, models[1].DefaultMaxTokens)
}

func TestDiscoverCodexModelsMapsMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{
			"models": [{
				"slug": "reasoning",
				"display_name": "Reasoning",
				"default_reasoning_level": "max",
				"supported_reasoning_levels": [
					{"effort": "xhigh"},
					{"effort": "max"},
					{"effort": "ultra"}
				],
				"visibility": "list",
				"priority": 1,
				"context_window": 200000,
				"input_modalities": ["text", "image"]
			}]
		}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	models, err := DiscoverModels(context.Background(), Config{
		ID:      chatgpt.ProviderID,
		BaseURL: server.URL,
	}, &mockResolver{})
	require.NoError(t, err)
	require.Len(t, models, 1)
	require.Equal(t, "reasoning", models[0].ID)
	require.Equal(t, "Reasoning", models[0].Name)
	require.Equal(t, int64(200000), models[0].ContextWindow)
	require.True(t, models[0].CanReason)
	require.Equal(t, []string{"xhigh", "max", "ultra"}, models[0].ReasoningLevels)
	require.Equal(t, "max", models[0].DefaultReasoningEffort)
	require.True(t, models[0].SupportsImages)
	require.Zero(t, models[0].DefaultMaxTokens)
}

func TestDiscoverCodexModelsErrors(t *testing.T) {
	tests := map[string]struct {
		status int
		body   string
	}{
		"HTTP error": {
			status: http.StatusInternalServerError,
			body:   `{}`,
		},
		"invalid JSON": {
			status: http.StatusOK,
			body:   `{`,
		},
		"missing models": {
			status: http.StatusOK,
			body:   `{"data":[]}`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, err := w.Write([]byte(test.body))
				require.NoError(t, err)
			}))
			t.Cleanup(server.Close)

			models, err := DiscoverModels(context.Background(), Config{
				ID:             chatgpt.ProviderID,
				BaseURL:        server.URL,
				ExistingModels: []catwalk.Model{{ID: "explicit"}},
			}, &mockResolver{})
			require.Error(t, err)
			require.Nil(t, models)
		})
	}
}

func modelIDs(models []catwalk.Model) []string {
	ids := make([]string, len(models))
	for index, model := range models {
		ids[index] = model.ID
	}
	return ids
}
