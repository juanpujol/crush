package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"charm.land/fantasy"
	"charm.land/fantasy/providers/openai"
	openaisdk "github.com/openai/openai-go/v3/option"
)

type codexProvider struct {
	fantasy.Provider
}

func (p codexProvider) LanguageModel(ctx context.Context, modelID string) (fantasy.LanguageModel, error) {
	model, err := p.Provider.LanguageModel(ctx, modelID)
	if err != nil {
		return nil, err
	}
	return codexLanguageModel{LanguageModel: model}, nil
}

type codexLanguageModel struct {
	fantasy.LanguageModel
}

func (m codexLanguageModel) Generate(ctx context.Context, call fantasy.Call) (*fantasy.Response, error) {
	return m.LanguageModel.Generate(withCodexReasoningReplay(ctx, call.Prompt), call)
}

func (m codexLanguageModel) Stream(ctx context.Context, call fantasy.Call) (fantasy.StreamResponse, error) {
	return m.LanguageModel.Stream(withCodexReasoningReplay(ctx, call.Prompt), call)
}

func (m codexLanguageModel) GenerateObject(ctx context.Context, call fantasy.ObjectCall) (*fantasy.ObjectResponse, error) {
	return m.LanguageModel.GenerateObject(withCodexReasoningReplay(ctx, call.Prompt), call)
}

func (m codexLanguageModel) StreamObject(ctx context.Context, call fantasy.ObjectCall) (fantasy.ObjectStreamResponse, error) {
	return m.LanguageModel.StreamObject(withCodexReasoningReplay(ctx, call.Prompt), call)
}

type codexReasoningReplayContextKey struct{}

type codexReasoningReplay struct {
	BaseInputItems int
	Items          []codexReasoningReplayItem
}

type codexReasoningReplayItem struct {
	InputIndex       int
	ID               string
	EncryptedContent string
	Summary          []string
}

func withCodexReasoningReplay(ctx context.Context, prompt fantasy.Prompt) context.Context {
	replay := codexReasoningReplayForPrompt(prompt)
	if len(replay.Items) == 0 {
		return ctx
	}
	return context.WithValue(ctx, codexReasoningReplayContextKey{}, replay)
}

func codexReasoningReplayForPrompt(prompt fantasy.Prompt) codexReasoningReplay {
	var replay codexReasoningReplay
	for _, message := range prompt {
		switch message.Role {
		case fantasy.MessageRoleSystem:
			if messageHasText(message) {
				replay.BaseInputItems++
			}
		case fantasy.MessageRoleUser:
			if messageHasUserInput(message) {
				replay.BaseInputItems++
			}
		case fantasy.MessageRoleAssistant:
			for _, part := range message.Content {
				switch part.GetType() {
				case fantasy.ContentTypeText:
					replay.BaseInputItems++
				case fantasy.ContentTypeToolCall:
					toolCall, ok := fantasy.AsContentType[fantasy.ToolCallPart](part)
					if ok && !toolCall.ProviderExecuted {
						replay.BaseInputItems++
					}
				case fantasy.ContentTypeReasoning:
					reasoning, ok := fantasy.AsContentType[fantasy.ReasoningPart](part)
					if !ok {
						continue
					}
					metadata := openai.GetReasoningMetadata(reasoning.ProviderOptions)
					if metadata == nil || metadata.ItemID == "" || metadata.EncryptedContent == nil {
						continue
					}
					replay.Items = append(replay.Items, codexReasoningReplayItem{
						InputIndex:       replay.BaseInputItems,
						ID:               metadata.ItemID,
						EncryptedContent: *metadata.EncryptedContent,
						Summary:          metadata.Summary,
					})
				}
			}
		case fantasy.MessageRoleTool:
			for _, part := range message.Content {
				if part.GetType() != fantasy.ContentTypeToolResult {
					continue
				}
				result, ok := fantasy.AsContentType[fantasy.ToolResultPart](part)
				if !ok || result.ProviderExecuted {
					continue
				}
				replay.BaseInputItems++
				if media, ok := fantasy.AsToolResultOutputType[fantasy.ToolResultOutputContentMedia](result.Output); ok &&
					strings.HasPrefix(media.MediaType, "image/") {
					replay.BaseInputItems++
				}
			}
		}
	}
	return replay
}

func messageHasText(message fantasy.Message) bool {
	for _, part := range message.Content {
		if text, ok := fantasy.AsContentType[fantasy.TextPart](part); ok && strings.TrimSpace(text.Text) != "" {
			return true
		}
	}
	return false
}

func messageHasUserInput(message fantasy.Message) bool {
	for _, part := range message.Content {
		switch part.GetType() {
		case fantasy.ContentTypeText:
			return true
		case fantasy.ContentTypeFile:
			file, ok := fantasy.AsContentType[fantasy.FilePart](part)
			if ok && (strings.HasPrefix(file.MediaType, "image/") || file.MediaType == "application/pdf") {
				return true
			}
		}
	}
	return false
}

func codexReasoningReplayOption() openaisdk.RequestOption {
	return openaisdk.WithMiddleware(func(req *http.Request, next openaisdk.MiddlewareNext) (*http.Response, error) {
		replay, ok := req.Context().Value(codexReasoningReplayContextKey{}).(codexReasoningReplay)
		if !ok || len(replay.Items) == 0 || !strings.HasSuffix(req.URL.Path, "/responses") {
			return next(req)
		}
		if err := injectCodexReasoningReplay(req, replay); err != nil {
			return nil, err
		}
		return next(req)
	})
}

func injectCodexReasoningReplay(req *http.Request, replay codexReasoningReplay) error {
	if req.Body == nil {
		return fmt.Errorf("inject Codex reasoning replay: request body is missing")
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("inject Codex reasoning replay: read request body: %w", err)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("inject Codex reasoning replay: decode request body: %w", err)
	}
	var input []json.RawMessage
	if err := json.Unmarshal(payload["input"], &input); err != nil {
		return fmt.Errorf("inject Codex reasoning replay: decode request input: %w", err)
	}

	existing := make(map[string]struct{})
	for _, item := range input {
		var identity struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if json.Unmarshal(item, &identity) == nil && identity.Type == "reasoning" {
			existing[identity.ID] = struct{}{}
		}
	}

	indexShift := len(input) - replay.BaseInputItems
	inserted := 0
	for _, item := range replay.Items {
		if _, ok := existing[item.ID]; ok {
			continue
		}
		reasoning, err := marshalCodexReasoningReplayItem(item)
		if err != nil {
			return err
		}
		index := item.InputIndex + indexShift + inserted
		index = max(0, min(index, len(input)))
		input = append(input, nil)
		copy(input[index+1:], input[index:])
		input[index] = reasoning
		inserted++
	}

	payload["input"], err = json.Marshal(input)
	if err != nil {
		return fmt.Errorf("inject Codex reasoning replay: encode request input: %w", err)
	}
	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("inject Codex reasoning replay: encode request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(updatedBody))
	req.ContentLength = int64(len(updatedBody))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(updatedBody)), nil
	}
	return nil
}

func marshalCodexReasoningReplayItem(item codexReasoningReplayItem) (json.RawMessage, error) {
	summary := make([]map[string]string, 0, len(item.Summary))
	for _, text := range item.Summary {
		summary = append(summary, map[string]string{
			"type": "summary_text",
			"text": text,
		})
	}
	encoded, err := json.Marshal(map[string]any{
		"type":              "reasoning",
		"id":                item.ID,
		"summary":           summary,
		"encrypted_content": item.EncryptedContent,
	})
	if err != nil {
		return nil, fmt.Errorf("inject Codex reasoning replay: encode reasoning item: %w", err)
	}
	return encoded, nil
}
