package admin

import (
	"testing"

	"github.com/gin-gonic/gin/binding"
	"github.com/stretchr/testify/require"
)

func TestGroupRequestValidationAcceptsSupportedPlatforms(t *testing.T) {
	platforms := []string{
		"anthropic",
		"openai",
		"gemini",
		"antigravity",
		"kiro",
		"grok",
		"windsurf",
	}

	for _, platform := range platforms {
		createReq := CreateGroupRequest{Name: platform + "-default", Platform: platform}
		require.NoError(t, binding.Validator.ValidateStruct(createReq))

		updateReq := UpdateGroupRequest{Platform: platform}
		require.NoError(t, binding.Validator.ValidateStruct(updateReq))
	}
}
