package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"charm.land/catwalk/pkg/catwalk"
	"charm.land/fantasy"
	"charm.land/fantasy/providers/openai"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
	"github.com/charmbracelet/crush/internal/session"
	"github.com/stretchr/testify/require"
)

func TestCodexResponsesTransport(t *testing.T) {
	t.Parallel()

	requestBody := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/responses", r.URL.Path)
		require.Equal(t, "Bearer access-token", r.Header.Get("Authorization"))
		require.Equal(t, "account-1", r.Header.Get(chatgpt.AccountIDHeader))
		require.Equal(t, chatgpt.Originator, r.Header.Get(chatgpt.OriginatorHeader))
		require.Equal(t, "true", r.Header.Get(chatgpt.FedRAMPHeader))

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		requestBody <- body

		w.Header().Set("Content-Type", "text/event-stream")
		events := []string{
			codexSSEEvent("response.created", `{"type":"response.created","response":{"id":"resp_01","status":"in_progress","output":[]}}`),
			codexSSEEvent("response.output_item.added", `{"type":"response.output_item.added","output_index":0,"item":{"id":"rs_01","type":"reasoning","encrypted_content":"opaque-reasoning","summary":[]}}`),
			codexSSEEvent("response.output_item.done", `{"type":"response.output_item.done","output_index":0,"item":{"id":"rs_01","type":"reasoning","encrypted_content":"opaque-reasoning","summary":[]}}`),
			codexSSEEvent("response.output_item.added", `{"type":"response.output_item.added","output_index":1,"item":{"id":"msg_01","type":"message","role":"assistant","status":"in_progress","content":[]}}`),
			codexSSEEvent("response.output_text.delta", `{"type":"response.output_text.delta","output_index":1,"content_index":0,"item_id":"msg_01","delta":"hello"}`),
			codexSSEEvent("response.output_item.done", `{"type":"response.output_item.done","output_index":1,"item":{"id":"msg_01","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"hello","annotations":[]}]}}`),
			codexSSEEvent("response.output_item.added", `{"type":"response.output_item.added","output_index":2,"item":{"id":"fc_01","type":"function_call","call_id":"call_01","name":"read_file","arguments":"","status":"in_progress"}}`),
			codexSSEEvent("response.function_call_arguments.delta", `{"type":"response.function_call_arguments.delta","output_index":2,"item_id":"fc_01","delta":"{\"path\":\"README.md\"}"}`),
			codexSSEEvent("response.output_item.done", `{"type":"response.output_item.done","output_index":2,"item":{"id":"fc_01","type":"function_call","call_id":"call_01","name":"read_file","arguments":"{\"path\":\"README.md\"}","status":"completed"}}`),
			codexSSEEvent("response.completed", `{"type":"response.completed","response":{"id":"resp_01","status":"completed","output":[],"usage":{"input_tokens":12,"output_tokens":8,"total_tokens":20}}}`),
		}
		for _, event := range events {
			_, err := w.Write([]byte(event))
			require.NoError(t, err)
		}
	}))
	t.Cleanup(server.Close)

	store := config.NewTestStore(&config.Config{Options: &config.Options{}})
	coordinator := &coordinator{cfg: store}
	provider, err := coordinator.buildOpenaiProvider(server.URL, "access-token", map[string]string{
		chatgpt.AccountIDHeader:  "account-1",
		chatgpt.OriginatorHeader: chatgpt.Originator,
		chatgpt.FedRAMPHeader:    "true",
	}, chatgpt.ProviderID)
	require.NoError(t, err)
	languageModel, err := provider.LanguageModel(context.Background(), "gpt-5-codex")
	require.NoError(t, err)

	model := Model{
		CatwalkCfg: catwalk.Model{
			ID:                     "gpt-5-codex",
			CanReason:              true,
			ReasoningLevels:        []string{"xhigh", "max", "ultra"},
			DefaultReasoningEffort: "max",
		},
		ModelCfg: config.SelectedModel{
			Provider:        chatgpt.ProviderID,
			ReasoningEffort: "ultra",
		},
	}
	stream, err := languageModel.Stream(context.Background(), fantasy.Call{
		Prompt: fantasy.Prompt{{
			Role: fantasy.MessageRoleUser,
			Content: []fantasy.MessagePart{
				fantasy.TextPart{Text: "Inspect the repository."},
			},
		}},
		ProviderOptions: getProviderOptions(model, config.ProviderConfig{
			ID:   chatgpt.ProviderID,
			Type: catwalk.TypeOpenAI,
		}),
	})
	require.NoError(t, err)

	var (
		hasTextDelta          bool
		hasToolCall           bool
		hasEncryptedReasoning bool
		finishUsage           fantasy.Usage
	)
	for part := range stream {
		require.NoError(t, part.Error)
		switch part.Type {
		case fantasy.StreamPartTypeTextDelta:
			hasTextDelta = part.Delta == "hello"
		case fantasy.StreamPartTypeToolCall:
			hasToolCall = part.ToolCallName == "read_file" &&
				part.ToolCallInput == `{"path":"README.md"}`
		case fantasy.StreamPartTypeReasoningEnd:
			metadata, ok := part.ProviderMetadata[openai.Name].(*openai.ResponsesReasoningMetadata)
			require.True(t, ok)
			hasEncryptedReasoning = metadata.EncryptedContent != nil &&
				*metadata.EncryptedContent == "opaque-reasoning"
		case fantasy.StreamPartTypeFinish:
			finishUsage = part.Usage
		}
	}
	require.True(t, hasTextDelta)
	require.True(t, hasToolCall)
	require.True(t, hasEncryptedReasoning)
	require.Equal(t, int64(12), finishUsage.InputTokens)
	require.Equal(t, int64(8), finishUsage.OutputTokens)

	body := <-requestBody
	require.Equal(t, "gpt-5-codex", body["model"])
	require.Nil(t, body["max_output_tokens"])
	require.Equal(t, []any{"reasoning.encrypted_content"}, body["include"])
	reasoning, ok := body["reasoning"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "ultra", reasoning["effort"])

	encryptedContent := "opaque-reasoning"
	secondStream, err := languageModel.Stream(context.Background(), fantasy.Call{
		Prompt: fantasy.Prompt{
			{
				Role: fantasy.MessageRoleSystem,
				Content: []fantasy.MessagePart{
					fantasy.TextPart{Text: "Be concise."},
				},
			},
			{
				Role: fantasy.MessageRoleUser,
				Content: []fantasy.MessagePart{
					fantasy.TextPart{Text: "Inspect the repository."},
				},
			},
			{
				Role: fantasy.MessageRoleAssistant,
				Content: []fantasy.MessagePart{
					fantasy.ReasoningPart{
						ProviderOptions: fantasy.ProviderOptions{
							openai.Name: &openai.ResponsesReasoningMetadata{
								ItemID:           "rs_01",
								EncryptedContent: &encryptedContent,
							},
						},
					},
					fantasy.ToolCallPart{
						ToolCallID: "call_01",
						ToolName:   "read_file",
						Input:      `{"path":"README.md"}`,
					},
				},
			},
			{
				Role: fantasy.MessageRoleTool,
				Content: []fantasy.MessagePart{
					fantasy.ToolResultPart{
						ToolCallID: "call_01",
						Output: fantasy.ToolResultOutputContentText{
							Text: "file contents",
						},
					},
				},
			},
		},
		ProviderOptions: getProviderOptions(model, config.ProviderConfig{
			ID:   chatgpt.ProviderID,
			Type: catwalk.TypeOpenAI,
		}),
	})
	require.NoError(t, err)
	for part := range secondStream {
		require.NoError(t, part.Error)
	}
	roundTrip := <-requestBody
	roundTripBody, err := json.Marshal(roundTrip)
	require.NoError(t, err)
	require.Contains(t, string(roundTripBody), `"type":"reasoning"`)
	require.Contains(t, string(roundTripBody), `"encrypted_content":"opaque-reasoning"`)
	require.Contains(t, string(roundTripBody), `"type":"function_call"`)
	require.Contains(t, string(roundTripBody), `"type":"function_call_output"`)

	input, ok := roundTrip["input"].([]any)
	require.True(t, ok)
	require.Len(t, input, 5)
	require.Equal(t, "developer", inputItemField(t, input[0], "role"))
	require.Equal(t, "user", inputItemField(t, input[1], "role"))
	require.Equal(t, "reasoning", inputItemField(t, input[2], "type"))
	require.Equal(t, "function_call", inputItemField(t, input[3], "type"))
	require.Equal(t, "function_call_output", inputItemField(t, input[4], "type"))
}

func TestCodexFlatRateUsageAccounting(t *testing.T) {
	t.Parallel()

	currentSession := &session.Session{ID: "session-id", Cost: 1.25}
	model := Model{
		CatwalkCfg: catwalk.Model{
			CostPer1MIn:        10,
			CostPer1MOut:       20,
			CostPer1MOutCached: 5,
		},
		FlatRate: true,
	}
	usage := fantasy.Usage{
		InputTokens:     1000,
		OutputTokens:    2000,
		CacheReadTokens: 500,
	}

	agent := &sessionAgent{}
	agent.updateSessionUsage(model, currentSession, usage, nil, false)
	require.Equal(t, 1.25, currentSession.Cost)
	require.Equal(t, int64(1500), currentSession.PromptTokens)
	require.Equal(t, int64(2000), currentSession.CompletionTokens)
}

func TestCodexReasoningEffortsRemainUnmodified(t *testing.T) {
	t.Parallel()

	for _, effort := range []string{"xhigh", "max", "ultra"} {
		t.Run(effort, func(t *testing.T) {
			t.Parallel()

			options := getProviderOptions(Model{
				CatwalkCfg: catwalk.Model{
					ID:              "gpt-5-codex",
					CanReason:       true,
					ReasoningLevels: []string{"xhigh", "max", "ultra"},
				},
				ModelCfg: config.SelectedModel{
					Provider:        chatgpt.ProviderID,
					ReasoningEffort: effort,
				},
			}, config.ProviderConfig{
				ID:   chatgpt.ProviderID,
				Type: catwalk.TypeOpenAI,
			})
			parsed, ok := options[openai.Name].(*openai.ResponsesProviderOptions)
			require.True(t, ok)
			require.NotNil(t, parsed.ReasoningEffort)
			require.Equal(t, effort, string(*parsed.ReasoningEffort))
			require.Contains(t, parsed.Include, openai.IncludeReasoningEncryptedContent)
		})
	}
}

func codexSSEEvent(event, data string) string {
	return "event: " + event + "\ndata: " + data + "\n\n"
}

func inputItemField(t *testing.T, value any, field string) string {
	t.Helper()
	item, ok := value.(map[string]any)
	require.True(t, ok)
	fieldValue, ok := item[field].(string)
	require.True(t, ok)
	return fieldValue
}
