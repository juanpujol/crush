package dialog

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/ui/common"
)

// APIKeyInputID is the identifier for the model selection dialog.
const APIKeyInputID = "api_key_input"

// APIKeyInput represents a model selection dialog.
type APIKeyInput struct {
	com *common.Common

	provider catwalk.Provider
	modelID  string

	width int

	keyMap struct {
		Submit key.Binding
		Close  key.Binding
	}
	input textinput.Model
	help  help.Model
}

var _ Dialog = (*APIKeyInput)(nil)

// NewAPIKeyInput creates a new Models dialog.
func NewAPIKeyInput(com *common.Common, provider catwalk.Provider, modelID string) (*APIKeyInput, error) {
	t := com.Styles

	m := APIKeyInput{}
	m.com = com
	m.provider = provider
	m.modelID = modelID
	m.width = 60

	m.input = textinput.New()
	m.input.SetVirtualCursor(false)
	m.input.Placeholder = "Enter you API key..."
	m.input.SetStyles(com.Styles.TextInput)
	m.input.Focus()
	m.input.SetWidth(m.width - t.Dialog.InputPrompt.GetHorizontalFrameSize() - 1) // (1) cursor padding

	m.help = help.New()
	m.help.Styles = t.DialogHelpStyles()

	m.keyMap.Submit = key.NewBinding(
		key.WithKeys("enter", "ctrl+y"),
		key.WithHelp("enter", "submit"),
	)
	m.keyMap.Close = CloseKey

	return &m, nil
}

// ID implements Dialog.
func (m *APIKeyInput) ID() string {
	return APIKeyInputID
}

// Update implements tea.Model.
func (m *APIKeyInput) Update(msg tea.Msg) tea.Msg {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, m.keyMap.Close):
			return CloseMsg{}
		case key.Matches(msg, m.keyMap.Submit):
			panic("TODO")
		default:
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return cmd
		}
	}
	return nil
}

// View implements tea.Model.
func (m *APIKeyInput) View() string {
	t := m.com.Styles

	textStyle := t.Dialog.SecondaryText
	helpStyle := t.Dialog.HelpView
	dialogStyle := t.Dialog.View.Width(m.width)
	inputStyle := t.Dialog.InputPrompt
	helpStyle = helpStyle.Width(m.width - dialogStyle.GetHorizontalFrameSize())

	content := strings.Join([]string{
		m.headerView(),
		inputStyle.Render(m.input.View()),
		textStyle.Render("This will be written in your global configuration:"),
		textStyle.Render(config.GlobalConfigData()),
		"",
		helpStyle.Render(m.help.View(m)),
	}, "\n")

	return dialogStyle.Render(content)
}

func (m *APIKeyInput) headerView() string {
	t := m.com.Styles
	titleStyle := t.Dialog.Title
	dialogStyle := t.Dialog.View.Width(m.width)

	headerOffset := titleStyle.GetHorizontalFrameSize() + dialogStyle.GetHorizontalFrameSize()
	return common.DialogTitle(t, m.dialogTitle(), m.width-headerOffset)
}

func (m *APIKeyInput) dialogTitle() string {
	t := m.com.Styles
	titleStyle := t.Dialog.Title
	textStyle := t.Dialog.TitleText
	accentStyle := t.Dialog.TitleAccent

	return titleStyle.Render(
		textStyle.Render("Enter your ") + accentStyle.Render(fmt.Sprintf("%s Key", m.provider.Name)) + textStyle.Render("."),
	)
}

// FullHelp returns the full help view.
func (m *APIKeyInput) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{
			m.keyMap.Submit,
			m.keyMap.Close,
		},
	}
}

// ShortHelp returns the full help view.
func (m *APIKeyInput) ShortHelp() []key.Binding {
	return []key.Binding{
		m.keyMap.Submit,
		m.keyMap.Close,
	}
}
