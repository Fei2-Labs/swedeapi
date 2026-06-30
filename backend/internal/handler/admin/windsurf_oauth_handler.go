package admin

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type WindsurfOAuthHandler struct {
	windsurfAuthService *service.WindsurfAuthService
}

func NewWindsurfOAuthHandler(windsurfAuthService *service.WindsurfAuthService) *WindsurfOAuthHandler {
	return &WindsurfOAuthHandler{windsurfAuthService: windsurfAuthService}
}

type WindsurfImportTokenRequest struct {
	Token   string `json:"token" binding:"required"`
	ProxyID *int64 `json:"proxy_id"`
}

type WindsurfPasswordLoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	ProxyID  *int64 `json:"proxy_id"`
}

func (h *WindsurfOAuthHandler) ImportToken(c *gin.Context) {
	var req WindsurfImportTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}
	result, err := h.windsurfAuthService.ImportToken(c.Request.Context(), &service.WindsurfImportTokenInput{
		Token:   strings.TrimSpace(req.Token),
		ProxyID: req.ProxyID,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *WindsurfOAuthHandler) LoginWithPassword(c *gin.Context) {
	var req WindsurfPasswordLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}
	result, err := h.windsurfAuthService.LoginWithPassword(c.Request.Context(), &service.WindsurfPasswordLoginInput{
		Email:    strings.TrimSpace(req.Email),
		Password: req.Password,
		ProxyID:  req.ProxyID,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
