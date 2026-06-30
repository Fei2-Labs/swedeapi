package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/httpclient"
)

const (
	windsurfCheckLoginMethodURL = "https://windsurf.com/_backend/exa.seat_management_pb.SeatManagementService/CheckUserLoginMethod"
	windsurfConnectionsURL      = "https://windsurf.com/_devin-auth/connections"
	windsurfPasswordLoginURL    = "https://windsurf.com/_devin-auth/password/login"
	windsurfPostAuthURLNew      = "https://windsurf.com/_backend/exa.seat_management_pb.SeatManagementService/WindsurfPostAuth"
	windsurfPostAuthURLLegacy   = "https://server.self-serve.windsurf.com/exa.seat_management_pb.SeatManagementService/WindsurfPostAuth"
	windsurfRegisterURLNew      = "https://register.windsurf.com/exa.seat_management_pb.SeatManagementService/RegisterUser"
	windsurfRegisterURLLegacy   = "https://api.codeium.com/register_user/"
)

var (
	windsurfSessionTokenPattern = regexp.MustCompile(`devin-session-token\$[a-zA-Z0-9._-]+`)
)

type WindsurfAuthService struct {
	proxyRepo ProxyRepository
}

func NewWindsurfAuthService(proxyRepo ProxyRepository) *WindsurfAuthService {
	return &WindsurfAuthService{proxyRepo: proxyRepo}
}

type WindsurfImportTokenInput struct {
	Token   string
	ProxyID *int64
}

type WindsurfPasswordLoginInput struct {
	Email    string
	Password string
	ProxyID  *int64
}

type WindsurfTokenInfo struct {
	APIKey       string `json:"api_key"`
	Name         string `json:"name,omitempty"`
	Email        string `json:"email,omitempty"`
	APIServerURL string `json:"api_server_url,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
	AuthMethod   string `json:"auth_method,omitempty"`
}

type windsurfHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

type windsurfLoginMethodProbe struct {
	UserExists  *bool
	HasPassword *bool
}

type windsurfPostAuthPayload struct {
	SessionToken string
	AccountID    string
	PrimaryOrgID string
	RawMessage   string
}

func (s *WindsurfAuthService) ImportToken(ctx context.Context, input *WindsurfImportTokenInput) (*WindsurfTokenInfo, error) {
	if input == nil {
		return nil, infraerrors.BadRequest("WINDSURF_TOKEN_REQUIRED", "token is required")
	}
	token := strings.TrimSpace(input.Token)
	if token == "" {
		return nil, infraerrors.BadRequest("WINDSURF_TOKEN_REQUIRED", "token is required")
	}

	client, err := s.httpClient(ctx, input.ProxyID)
	if err != nil {
		return nil, err
	}

	payload := map[string]string{"firebase_id_token": token}
	headers := map[string]string{
		"Content-Type":             "application/json",
		"Accept":                   "application/json",
		"Connect-Protocol-Version": "1",
		"User-Agent":               "windsurf/1.9600.41",
	}

	var attempts []string
	for _, endpoint := range []string{windsurfRegisterURLNew, windsurfRegisterURLLegacy} {
		resp, reqErr := s.doJSONRequest(ctx, client, endpoint, headers, payload)
		if reqErr != nil {
			attempts = append(attempts, fmt.Sprintf("%s: %v", endpoint, reqErr))
			continue
		}
		body := parseLooseJSON(resp.Body)
		apiKey := windsurfFirstNonEmpty(anyToString(body["api_key"]), anyToString(body["apiKey"]))
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && apiKey != "" {
			return &WindsurfTokenInfo{
				APIKey:       apiKey,
				Name:         windsurfFirstNonEmpty(anyToString(body["name"]), anyToString(body["email"])),
				Email:        anyToString(body["email"]),
				APIServerURL: windsurfFirstNonEmpty(anyToString(body["api_server_url"]), anyToString(body["apiServerUrl"])),
				AuthMethod:   "token",
			}, nil
		}
		attempts = append(attempts, fmt.Sprintf("%s: HTTP %d %s", endpoint, resp.StatusCode, compactBody(resp.Body)))
	}

	return nil, infraerrors.BadRequest("WINDSURF_REGISTER_FAILED", fmt.Sprintf("windsurf token import failed: %s", strings.Join(attempts, " | ")))
}

func (s *WindsurfAuthService) LoginWithPassword(ctx context.Context, input *WindsurfPasswordLoginInput) (*WindsurfTokenInfo, error) {
	if input == nil {
		return nil, infraerrors.BadRequest("WINDSURF_LOGIN_REQUIRED", "email and password are required")
	}
	email := strings.TrimSpace(input.Email)
	password := strings.TrimSpace(input.Password)
	if email == "" || password == "" {
		return nil, infraerrors.BadRequest("WINDSURF_LOGIN_REQUIRED", "email and password are required")
	}

	client, err := s.httpClient(ctx, input.ProxyID)
	if err != nil {
		return nil, err
	}

	probe, err := s.checkLoginMethod(ctx, client, email)
	if err != nil {
		return nil, err
	}
	if probe != nil {
		if probe.UserExists != nil && !*probe.UserExists {
			return nil, infraerrors.BadRequest("WINDSURF_EMAIL_NOT_FOUND", "Windsurf account not found")
		}
		if probe.HasPassword != nil && !*probe.HasPassword {
			return nil, infraerrors.BadRequest("WINDSURF_NO_PASSWORD", "This Windsurf account does not have a password login. Token import works now; Google and GitHub login are not wired yet.")
		}
	}

	loginResp, err := s.doJSONRequest(ctx, client, windsurfPasswordLoginURL, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
		"Origin":       "https://windsurf.com",
		"Referer":      "https://windsurf.com/account/login",
		"User-Agent":   "Mozilla/5.0",
	}, map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return nil, infraerrors.BadRequest("WINDSURF_LOGIN_FAILED", fmt.Sprintf("windsurf login failed: %v", err))
	}
	if err := windsurfAuthErrorFromResponse(loginResp); err != nil {
		return nil, err
	}

	body := parseLooseJSON(loginResp.Body)
	auth1Token := anyToString(body["token"])
	if auth1Token == "" {
		return nil, infraerrors.BadRequest("WINDSURF_AUTH1_TOKEN_MISSING", "Windsurf login succeeded but did not return an auth token")
	}

	postAuth, err := s.postAuth(ctx, client, auth1Token)
	if err != nil {
		return nil, err
	}
	if postAuth.SessionToken == "" {
		return nil, infraerrors.BadRequest("WINDSURF_SESSION_TOKEN_MISSING", "Windsurf login succeeded but did not return a session token")
	}

	return &WindsurfTokenInfo{
		APIKey:       postAuth.SessionToken,
		Name:         email,
		Email:        email,
		SessionToken: postAuth.SessionToken,
		AuthMethod:   "password",
	}, nil
}

func (s *WindsurfAuthService) checkLoginMethod(ctx context.Context, client *http.Client, email string) (*windsurfLoginMethodProbe, error) {
	connectResp, err := s.doJSONRequest(ctx, client, windsurfCheckLoginMethodURL, map[string]string{
		"Content-Type":             "application/json",
		"Accept":                   "application/json",
		"Connect-Protocol-Version": "1",
		"Origin":                   "https://windsurf.com",
		"Referer":                  "https://windsurf.com/account/login",
		"User-Agent":               "Mozilla/5.0",
	}, map[string]string{"email": email})
	if err == nil {
		body := parseLooseJSON(connectResp.Body)
		if userExists, ok := anyToBool(body["userExists"]); ok {
			probe := &windsurfLoginMethodProbe{UserExists: &userExists}
			if hasPassword, hasPasswordOK := anyToBool(body["hasPassword"]); hasPasswordOK {
				probe.HasPassword = &hasPassword
			}
			return probe, nil
		}
		if hasPassword, ok := anyToBool(body["hasPassword"]); ok {
			probe := &windsurfLoginMethodProbe{HasPassword: &hasPassword}
			return probe, nil
		}
	}

	fallbackResp, fallbackErr := s.doJSONRequest(ctx, client, windsurfConnectionsURL, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
		"Origin":       "https://windsurf.com",
		"Referer":      "https://windsurf.com/account/login",
		"User-Agent":   "Mozilla/5.0",
	}, map[string]string{
		"product": "windsurf",
		"email":   email,
	})
	if fallbackErr != nil {
		if err != nil {
			return nil, nil
		}
		return nil, nil
	}
	body := parseLooseJSON(fallbackResp.Body)
	if connections, ok := body["connections"].([]any); ok {
		for _, raw := range connections {
			conn, ok := raw.(map[string]any)
			if !ok || !strings.EqualFold(anyToString(conn["type"]), "email") {
				continue
			}
			enabled, enabledOK := anyToBool(conn["enabled"])
			if enabledOK {
				probe := &windsurfLoginMethodProbe{HasPassword: &enabled}
				return probe, nil
			}
		}
	}
	if authMethod, ok := body["auth_method"].(map[string]any); ok {
		if hasPassword, hasPasswordOK := anyToBool(authMethod["has_password"]); hasPasswordOK {
			probe := &windsurfLoginMethodProbe{HasPassword: &hasPassword}
			return probe, nil
		}
	}
	return nil, nil
}

func (s *WindsurfAuthService) postAuth(ctx context.Context, client *http.Client, auth1Token string) (*windsurfPostAuthPayload, error) {
	headers := map[string]string{
		"Content-Type":             "application/proto",
		"Accept":                   "application/json, text/plain, */*",
		"Connect-Protocol-Version": "1",
		"X-Devin-Auth1-Token":      auth1Token,
		"Referer":                  "https://windsurf.com/account/login",
		"Origin":                   "https://windsurf.com",
		"User-Agent":               "Mozilla/5.0",
	}

	var attempts []string
	for _, endpoint := range []string{windsurfPostAuthURLNew, windsurfPostAuthURLLegacy} {
		resp, err := s.doRawRequest(ctx, client, endpoint, headers, nil)
		if err != nil {
			attempts = append(attempts, fmt.Sprintf("%s: %v", endpoint, err))
			continue
		}
		payload := parsePostAuthPayload(resp.Body)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && payload.SessionToken != "" {
			return payload, nil
		}
		attempts = append(attempts, fmt.Sprintf("%s: HTTP %d %s", endpoint, resp.StatusCode, compactBody(resp.Body)))
	}
	return nil, infraerrors.BadRequest("WINDSURF_POSTAUTH_FAILED", fmt.Sprintf("windsurf session exchange failed: %s", strings.Join(attempts, " | ")))
}

func (s *WindsurfAuthService) httpClient(ctx context.Context, proxyID *int64) (*http.Client, error) {
	var proxyURL string
	if proxyID != nil {
		if s.proxyRepo == nil {
			return nil, infraerrors.BadRequest("WINDSURF_PROXY_UNAVAILABLE", "proxy repository is unavailable")
		}
		proxy, err := s.proxyRepo.GetByID(ctx, *proxyID)
		if err != nil {
			return nil, infraerrors.BadRequest("WINDSURF_PROXY_NOT_FOUND", fmt.Sprintf("proxy not found: %v", err))
		}
		if proxy != nil {
			proxyURL = proxy.URL()
		}
	}
	client, err := httpclient.GetClient(httpclient.Options{
		ProxyURL:              proxyURL,
		Timeout:               30 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	})
	if err != nil {
		return nil, infraerrors.BadRequest("WINDSURF_HTTP_CLIENT_FAILED", fmt.Sprintf("failed to build HTTP client: %v", err))
	}
	return client, nil
}

func (s *WindsurfAuthService) doJSONRequest(ctx context.Context, client *http.Client, endpoint string, headers map[string]string, payload any) (*windsurfHTTPResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return s.doRawRequest(ctx, client, endpoint, headers, body)
}

func (s *WindsurfAuthService) doRawRequest(ctx context.Context, client *http.Client, endpoint string, headers map[string]string, body []byte) (*windsurfHTTPResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if body != nil {
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	} else {
		req.Header.Set("Content-Length", "0")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &windsurfHTTPResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       respBody,
	}, nil
}

func windsurfAuthErrorFromResponse(resp *windsurfHTTPResponse) error {
	if resp == nil {
		return infraerrors.BadRequest("WINDSURF_LOGIN_FAILED", "windsurf login failed")
	}
	body := parseLooseJSON(resp.Body)
	detail := strings.TrimSpace(extractWindsurfDetail(body))
	if resp.StatusCode < 400 && detail == "" {
		return nil
	}
	switch strings.TrimSpace(detail) {
	case "EMAIL_NOT_FOUND":
		return infraerrors.BadRequest("WINDSURF_EMAIL_NOT_FOUND", "Windsurf account not found")
	case "INVALID_PASSWORD", "INVALID_LOGIN_CREDENTIALS", "Invalid email or password":
		return infraerrors.BadRequest("WINDSURF_INVALID_CREDENTIALS", "Invalid Windsurf email or password")
	case "No password set. Please log in with Google or GitHub.", "No password set":
		return infraerrors.BadRequest("WINDSURF_NO_PASSWORD", "This Windsurf account does not have a password login. Token import works now; Google and GitHub login are not wired yet.")
	case "USER_DISABLED":
		return infraerrors.BadRequest("WINDSURF_USER_DISABLED", "This Windsurf account is disabled")
	case "TOO_MANY_ATTEMPTS_TRY_LATER":
		return infraerrors.BadRequest("WINDSURF_TOO_MANY_ATTEMPTS", "Too many Windsurf login attempts. Try again later.")
	}
	if detail != "" {
		return infraerrors.BadRequest("WINDSURF_LOGIN_FAILED", detail)
	}
	return infraerrors.BadRequest("WINDSURF_LOGIN_FAILED", fmt.Sprintf("windsurf login failed with HTTP %d", resp.StatusCode))
}

func extractWindsurfDetail(body map[string]any) string {
	if body == nil {
		return ""
	}
	if detail, ok := body["detail"]; ok {
		switch value := detail.(type) {
		case string:
			return value
		case []any:
			parts := make([]string, 0, len(value))
			for _, item := range value {
				switch current := item.(type) {
				case string:
					parts = append(parts, current)
				case map[string]any:
					parts = append(parts, windsurfFirstNonEmpty(anyToString(current["msg"]), anyToString(current["type"])))
				default:
					parts = append(parts, fmt.Sprint(current))
				}
			}
			return strings.Join(parts, "; ")
		}
	}
	if errField := anyToString(body["error"]); errField != "" {
		return errField
	}
	if msg := anyToString(body["message"]); msg != "" {
		return msg
	}
	return ""
}

func parsePostAuthPayload(body []byte) *windsurfPostAuthPayload {
	raw := strings.TrimSpace(string(body))
	parsed := parseLooseJSON(body)
	payload := &windsurfPostAuthPayload{
		SessionToken: anyToString(parsed["sessionToken"]),
		AccountID:    anyToString(parsed["accountId"]),
		PrimaryOrgID: anyToString(parsed["primaryOrgId"]),
		RawMessage:   raw,
	}
	if payload.SessionToken == "" {
		payload.SessionToken = windsurfSessionTokenPattern.FindString(raw)
	}
	if payload.AccountID == "" {
		payload.AccountID = findPattern(raw, `account-[a-f0-9]+`)
	}
	if payload.PrimaryOrgID == "" {
		payload.PrimaryOrgID = findPattern(raw, `org-[a-f0-9]+`)
	}
	return payload
}

func parseLooseJSON(body []byte) map[string]any {
	if len(body) == 0 {
		return map[string]any{}
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return map[string]any{}
	}
	return parsed
}

func anyToString(value any) string {
	switch current := value.(type) {
	case string:
		return strings.TrimSpace(current)
	case json.Number:
		return current.String()
	case float64:
		return strings.TrimSpace(fmt.Sprintf("%v", current))
	case int:
		return fmt.Sprintf("%d", current)
	case int64:
		return fmt.Sprintf("%d", current)
	default:
		return ""
	}
}

func anyToBool(value any) (bool, bool) {
	switch current := value.(type) {
	case bool:
		return current, true
	case string:
		switch strings.ToLower(strings.TrimSpace(current)) {
		case "true", "1", "yes":
			return true, true
		case "false", "0", "no":
			return false, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}

func windsurfFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func compactBody(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "empty response"
	}
	if len(trimmed) > 200 {
		return trimmed[:200]
	}
	return trimmed
}

func findPattern(raw, pattern string) string {
	re := regexp.MustCompile(pattern)
	return re.FindString(raw)
}
