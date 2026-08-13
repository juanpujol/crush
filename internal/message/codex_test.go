package message

import (
	"testing"

	"charm.land/fantasy"
	"charm.land/fantasy/providers/openai"
	"github.com/stretchr/testify/require"
)

func TestReasoningResponsesDataSurvivesFinishAndReplay(t *testing.T) {
	t.Parallel()

	encrypted := "opaque-reasoning"
	metadata := &openai.ResponsesReasoningMetadata{
		ItemID:           "rs_01",
		EncryptedContent: &encrypted,
	}
	msg := &Message{Role: Assistant}
	msg.AppendReasoningContent("")
	msg.SetReasoningResponsesData(metadata)
	msg.FinishThinking()

	reasoning := msg.ReasoningContent()
	require.Same(t, metadata, reasoning.ResponsesData)
	require.NotZero(t, reasoning.FinishedAt)

	messages := msg.ToAIMessage()
	require.Len(t, messages, 1)
	require.Len(t, messages[0].Content, 1)
	part, ok := messages[0].Content[0].(fantasy.ReasoningPart)
	require.True(t, ok)
	require.Same(t, metadata, openai.GetReasoningMetadata(part.ProviderOptions))
}
