package discover

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/oauth/chatgpt"
)

// CodexCompatibilityVersion is the client version advertised to the Codex
// model catalog. It is intentionally independent from the Crush version.
const CodexCompatibilityVersion = "0.144.0"

type codexModelsResponse struct {
	Models *[]codexModel `json:"models"`
}

type codexModel struct {
	Slug                     string                `json:"slug"`
	DisplayName              string                `json:"display_name"`
	DefaultReasoningLevel    string                `json:"default_reasoning_level"`
	SupportedReasoningLevels []codexReasoningLevel `json:"supported_reasoning_levels"`
	Visibility               string                `json:"visibility"`
	Priority                 int                   `json:"priority"`
	ContextWindow            int64                 `json:"context_window"`
	InputModalities          []string              `json:"input_modalities"`
}

type codexReasoningLevel struct {
	Effort string `json:"effort"`
}

func discoverCodexModels(ctx context.Context, cfg Config, resolver Resolver) ([]catwalk.Model, error) {
	path := "/models?client_version=" + CodexCompatibilityVersion
	resp, err := doRequest(ctx, http.MethodGet, cfg.BaseURL, path, cfg.APIKey, cfg.ExtraHeaders, resolver, nil)
	if err != nil {
		return nil, fmt.Errorf("discover models for provider %s: %w", cfg.ID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discover models for provider %s: %s", cfg.ID, resp.Status)
	}

	var response codexModelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("discover models for provider %s: %w", cfg.ID, err)
	}
	if response.Models == nil {
		return nil, fmt.Errorf("discover models for provider %s: response is missing models", cfg.ID)
	}

	visible := make([]codexModel, 0, len(*response.Models))
	for _, model := range *response.Models {
		if model.Visibility == "list" {
			visible = append(visible, model)
		}
	}
	slices.SortStableFunc(visible, func(left, right codexModel) int {
		return cmp.Compare(left.Priority, right.Priority)
	})

	existing := make(map[string]struct{}, len(cfg.ExistingModels))
	result := make([]catwalk.Model, len(cfg.ExistingModels), len(cfg.ExistingModels)+len(visible))
	copy(result, cfg.ExistingModels)
	for _, model := range cfg.ExistingModels {
		existing[model.ID] = struct{}{}
	}
	for _, model := range visible {
		if model.Slug == "" {
			continue
		}
		if _, ok := existing[model.Slug]; ok {
			continue
		}

		reasoningLevels := make([]string, 0, len(model.SupportedReasoningLevels))
		for _, level := range model.SupportedReasoningLevels {
			if level.Effort != "" {
				reasoningLevels = append(reasoningLevels, level.Effort)
			}
		}
		result = append(result, catwalk.Model{
			ID:                     model.Slug,
			Name:                   cmp.Or(model.DisplayName, model.Slug),
			ContextWindow:          model.ContextWindow,
			CanReason:              len(reasoningLevels) > 0,
			ReasoningLevels:        reasoningLevels,
			DefaultReasoningEffort: model.DefaultReasoningLevel,
			SupportsImages:         slices.Contains(model.InputModalities, "image"),
		})
		existing[model.Slug] = struct{}{}
	}
	return result, nil
}

func isCodexProvider(cfg Config) bool {
	return cfg.ID == chatgpt.ProviderID
}
