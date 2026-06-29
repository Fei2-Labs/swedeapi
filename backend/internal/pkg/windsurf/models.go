package windsurf

// Model describes a WindsurfAPI model in OpenAI-compatible /models shape.
type Model struct {
	ID          string `json:"id"`
	Object      string `json:"object"`
	Created     int64  `json:"created,omitempty"`
	OwnedBy     string `json:"owned_by"`
	DisplayName string `json:"display_name,omitempty"`
}

var defaultModels = []Model{
	{ID: "claude-sonnet-4.6", Object: "model", OwnedBy: "windsurf", DisplayName: "Claude Sonnet 4.6"},
	{ID: "claude-opus-4.6", Object: "model", OwnedBy: "windsurf", DisplayName: "Claude Opus 4.6"},
	{ID: "claude-opus-4.6-thinking", Object: "model", OwnedBy: "windsurf", DisplayName: "Claude Opus 4.6 Thinking"},
	{ID: "gpt-5", Object: "model", OwnedBy: "windsurf", DisplayName: "GPT-5"},
	{ID: "gemini-2.5-flash", Object: "model", OwnedBy: "windsurf", DisplayName: "Gemini 2.5 Flash"},
	{ID: "grok", Object: "model", OwnedBy: "windsurf", DisplayName: "Grok"},
	{ID: "qwen", Object: "model", OwnedBy: "windsurf", DisplayName: "Qwen"},
	{ID: "kimi-k2", Object: "model", OwnedBy: "windsurf", DisplayName: "Kimi K2"},
	{ID: "glm", Object: "model", OwnedBy: "windsurf", DisplayName: "GLM"},
}

func DefaultModels() []Model {
	out := make([]Model, len(defaultModels))
	copy(out, defaultModels)
	return out
}

func DefaultModelIDs() []string {
	models := DefaultModels()
	ids := make([]string, 0, len(models))
	for _, model := range models {
		ids = append(ids, model.ID)
	}
	return ids
}

func DefaultModelMapping() map[string]string {
	mapping := make(map[string]string, len(defaultModels)+4)
	for _, model := range defaultModels {
		mapping[model.ID] = model.ID
	}
	mapping["claude-sonnet"] = "claude-sonnet-4.6"
	mapping["claude-opus"] = "claude-opus-4.6"
	mapping["claude-opus-thinking"] = "claude-opus-4.6-thinking"
	mapping["gemini-flash"] = "gemini-2.5-flash"
	return mapping
}
