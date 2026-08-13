// Package chatgpt implements ChatGPT device authorization for the Codex API.
package chatgpt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/crush/internal/oauth"
)

const (
	ProviderID   = "openai-codex"
	ProviderName = "OpenAI Codex"

	IssuerURL  = "https://auth.openai.com"
	BackendURL = "https://chatgpt.com/backend-api/codex"
	ClientID   = "app_EMoamEEZ73f0CkXaXp7hrann"

	AccountIDHeader  = "ChatGPT-Account-ID"
	FedRAMPHeader    = "X-OpenAI-Fedramp"
	OriginatorHeader = "Originator"
	Originator       = "crush"

	defaultPollTimeout = 15 * time.Minute
	defaultHTTPTimeout = 30 * time.Second
	revokeHTTPTimeout  = 10 * time.Second
)

var ErrAccountMismatch = errors.New("ChatGPT account changed during re-authentication; run `crush login codex --force` to switch accounts")

// Client performs ChatGPT device authorization and token refresh requests.
type Client struct {
	httpClient  *http.Client
	issuerURL   string
	clientID    string
	pollTimeout time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient replaces the HTTP client used for OAuth requests.
func WithHTTPClient(client *http.Client) Option {
	return func(target *Client) {
		if client != nil {
			target.httpClient = client
		}
	}
}

// WithIssuerURL replaces the OAuth issuer URL.
func WithIssuerURL(issuerURL string) Option {
	return func(target *Client) {
		target.issuerURL = strings.TrimRight(issuerURL, "/")
	}
}

// WithPollTimeout replaces the device authorization polling timeout.
func WithPollTimeout(timeout time.Duration) Option {
	return func(target *Client) {
		target.pollTimeout = timeout
	}
}

// NewClient returns a ChatGPT OAuth client using the production endpoints.
func NewClient(options ...Option) *Client {
	client := &Client{
		httpClient:  &http.Client{Timeout: defaultHTTPTimeout},
		issuerURL:   IssuerURL,
		clientID:    ClientID,
		pollTimeout: defaultPollTimeout,
	}
	for _, option := range options {
		option(client)
	}

	httpClient := *client.httpClient
	previousCheckRedirect := httpClient.CheckRedirect
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		issuer, err := url.Parse(client.issuerURL)
		if err != nil {
			return fmt.Errorf("parse ChatGPT issuer URL: %w", err)
		}
		if !sameOrigin(req.URL, issuer) {
			return errors.New("refusing cross-origin ChatGPT OAuth redirect")
		}
		if previousCheckRedirect != nil {
			return previousCheckRedirect(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	client.httpClient = &httpClient
	return client
}

// DeviceCode contains the user-facing code and the state needed to poll.
type DeviceCode struct {
	DeviceAuthID    string
	UserCode        string
	VerificationURL string
	Interval        time.Duration
}

// AuthorizationCode contains the one-time authorization response.
type AuthorizationCode struct {
	CodeVerifier      string
	AuthorizationCode string
}

// AuthResult contains credentials and routing metadata derived from the JWTs.
type AuthResult struct {
	Token              *oauth.Token
	AccountID          string
	FedRAMP            bool
	HasRoutingMetadata bool
}

type userCodeResponse struct {
	DeviceAuthID string      `json:"device_auth_id"`
	UserCode     string      `json:"user_code"`
	UserCodeAlt  string      `json:"usercode"`
	Interval     json.Number `json:"interval"`
}

type pollResponse struct {
	AuthorizationCode string `json:"authorization_code"`
	CodeChallenge     string `json:"code_challenge"`
	CodeVerifier      string `json:"code_verifier"`
}

type tokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type jwtClaims struct {
	ExpiresAt int64 `json:"exp"`
	Auth      struct {
		AccountID string `json:"chatgpt_account_id"`
		FedRAMP   bool   `json:"chatgpt_account_is_fedramp"`
	} `json:"https://api.openai.com/auth"`
}

// RequestDeviceCode starts the ChatGPT device authorization flow.
func (c *Client) RequestDeviceCode(ctx context.Context) (DeviceCode, error) {
	var result userCodeResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/accounts/deviceauth/usercode", map[string]string{
		"client_id": c.clientID,
	}, &result); err != nil {
		return DeviceCode{}, fmt.Errorf("request ChatGPT device code: %w", err)
	}

	userCode := result.UserCode
	if userCode == "" {
		userCode = result.UserCodeAlt
	}
	if result.DeviceAuthID == "" || userCode == "" {
		return DeviceCode{}, errors.New("request ChatGPT device code: response is missing required fields")
	}

	interval, err := strconv.ParseInt(string(result.Interval), 10, 64)
	if err != nil || interval < 0 || interval > int64((1<<63-1)/time.Second) {
		return DeviceCode{}, fmt.Errorf("request ChatGPT device code: invalid polling interval %q", result.Interval)
	}

	return DeviceCode{
		DeviceAuthID:    result.DeviceAuthID,
		UserCode:        userCode,
		VerificationURL: strings.TrimRight(c.issuerURL, "/") + "/codex/device",
		Interval:        time.Duration(interval) * time.Second,
	}, nil
}

// PollAuthorization waits for the user to authorize the device.
func (c *Client) PollAuthorization(ctx context.Context, device DeviceCode) (AuthorizationCode, error) {
	ctx, cancel := context.WithTimeout(ctx, c.pollTimeout)
	defer cancel()

	interval := device.Interval
	if interval <= 0 {
		interval = time.Second
	}

	for {
		var result pollResponse
		status, err := c.doJSONStatus(ctx, http.MethodPost, "/api/accounts/deviceauth/token", map[string]string{
			"device_auth_id": device.DeviceAuthID,
			"user_code":      device.UserCode,
		}, &result)
		if err == nil {
			if result.AuthorizationCode == "" || result.CodeChallenge == "" || result.CodeVerifier == "" {
				return AuthorizationCode{}, errors.New("poll ChatGPT authorization: response is missing required fields")
			}
			challenge := sha256.Sum256([]byte(result.CodeVerifier))
			if base64.RawURLEncoding.EncodeToString(challenge[:]) != result.CodeChallenge {
				return AuthorizationCode{}, errors.New("poll ChatGPT authorization: code verifier does not match challenge")
			}
			return AuthorizationCode{
				CodeVerifier:      result.CodeVerifier,
				AuthorizationCode: result.AuthorizationCode,
			}, nil
		}
		if status != http.StatusForbidden && status != http.StatusNotFound {
			return AuthorizationCode{}, fmt.Errorf("poll ChatGPT authorization: %w", err)
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return AuthorizationCode{}, fmt.Errorf("poll ChatGPT authorization: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

// ExchangeAuthorization exchanges an authorization code for credentials.
func (c *Client) ExchangeAuthorization(ctx context.Context, authorization AuthorizationCode) (AuthResult, error) {
	values := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorization.AuthorizationCode},
		"redirect_uri":  {strings.TrimRight(c.issuerURL, "/") + "/deviceauth/callback"},
		"client_id":     {c.clientID},
		"code_verifier": {authorization.CodeVerifier},
	}

	var response tokenResponse
	if err := c.doForm(ctx, "/oauth/token", values, &response); err != nil {
		return AuthResult{}, fmt.Errorf("exchange ChatGPT authorization: %w", err)
	}
	return authResult(response, "")
}

// Refresh rotates a ChatGPT OAuth token and validates that the account did
// not change.
func (c *Client) Refresh(ctx context.Context, current *oauth.Token, expectedAccountID string) (AuthResult, error) {
	if current == nil || current.RefreshToken == "" {
		return AuthResult{}, errors.New("refresh ChatGPT token: refresh token is missing")
	}

	var response tokenResponse
	_, err := c.doJSONStatus(ctx, http.MethodPost, "/oauth/token", map[string]string{
		"client_id":     c.clientID,
		"grant_type":    "refresh_token",
		"refresh_token": current.RefreshToken,
	}, &response)
	if err != nil {
		return AuthResult{}, fmt.Errorf("refresh ChatGPT token: %w", err)
	}

	if response.AccessToken == "" {
		response.AccessToken = current.AccessToken
	}
	if response.RefreshToken == "" {
		response.RefreshToken = current.RefreshToken
	}
	result, err := authResult(response, expectedAccountID)
	if err != nil {
		return AuthResult{}, fmt.Errorf("refresh ChatGPT token: %w", err)
	}
	if expectedAccountID != "" && result.AccountID != expectedAccountID {
		return AuthResult{}, ErrAccountMismatch
	}
	return result, nil
}

// Revoke invalidates the refresh token, falling back to the access token when
// no refresh token is available.
func (c *Client) Revoke(ctx context.Context, current *oauth.Token) error {
	if current == nil {
		return nil
	}
	token := current.RefreshToken
	tokenType := "refresh_token"
	request := map[string]string{
		"token":           token,
		"token_type_hint": tokenType,
		"client_id":       c.clientID,
	}
	if token == "" {
		token = current.AccessToken
		tokenType = "access_token"
		request = map[string]string{
			"token":           token,
			"token_type_hint": tokenType,
		}
	}
	if token == "" {
		return nil
	}

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal revoke request: %w", err)
	}
	revokeCtx, cancel := context.WithTimeout(ctx, revokeHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(revokeCtx, http.MethodPost, c.endpoint("/oauth/revoke"), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke ChatGPT token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("revoke ChatGPT token: status %d code %s", resp.StatusCode, readErrorCode(resp.Body))
	}
	return nil
}

func authResult(response tokenResponse, fallbackAccountID string) (AuthResult, error) {
	if response.AccessToken == "" || response.RefreshToken == "" {
		return AuthResult{}, errors.New("token response is missing required credentials")
	}

	accessClaims, err := parseJWT(response.AccessToken)
	if err != nil {
		return AuthResult{}, fmt.Errorf("parse access token: %w", err)
	}
	identityClaims := accessClaims
	if response.IDToken != "" {
		identityClaims, err = parseJWT(response.IDToken)
		if err != nil {
			return AuthResult{}, fmt.Errorf("parse ID token: %w", err)
		}
	}
	accountID := identityClaims.Auth.AccountID
	hasRoutingMetadata := accountID != ""
	if response.IDToken == "" && accountID == "" {
		accountID = fallbackAccountID
	}
	if accountID == "" {
		return AuthResult{}, errors.New("token response is missing ChatGPT account metadata")
	}

	expiresAt := accessClaims.ExpiresAt
	token := &oauth.Token{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		ExpiresIn:    response.ExpiresIn,
		ExpiresAt:    expiresAt,
	}
	if token.ExpiresAt == 0 {
		token.SetExpiresAt()
	} else {
		token.SetExpiresIn()
	}

	return AuthResult{
		Token:              token,
		AccountID:          accountID,
		FedRAMP:            identityClaims.Auth.FedRAMP,
		HasRoutingMetadata: hasRoutingMetadata,
	}, nil
}

func parseJWT(token string) (jwtClaims, error) {
	var claims jwtClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return claims, errors.New("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, fmt.Errorf("decode JWT payload: %w", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("decode JWT claims: %w", err)
	}
	return claims, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, requestBody, responseBody any) error {
	_, err := c.doJSONStatus(ctx, method, path, requestBody, responseBody)
	return err
}

func (c *Client) doJSONStatus(ctx context.Context, method, path string, requestBody, responseBody any) (int, error) {
	body, err := json.Marshal(requestBody)
	if err != nil {
		return 0, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.execute(req, responseBody)
}

func (c *Client) doForm(ctx context.Context, path string, values url.Values, responseBody any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(path), strings.NewReader(values.Encode()))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = c.execute(req, responseBody)
	return err
}

func (c *Client) execute(req *http.Request, responseBody any) (int, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		code := readErrorCode(resp.Body)
		return resp.StatusCode, &oauth.TokenExchangeError{
			StatusCode: resp.StatusCode,
			Body:       code,
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(responseBody); err != nil {
		return resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	return resp.StatusCode, nil
}

func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.issuerURL, "/") + "/" + strings.TrimLeft(path, "/")
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func readErrorCode(body io.Reader) string {
	var response struct {
		Code  string `json:"code"`
		Error any    `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(body, 1<<20)).Decode(&response); err != nil {
		return "unknown_error"
	}
	if response.Code != "" {
		return sanitizeErrorCode(response.Code)
	}
	switch value := response.Error.(type) {
	case string:
		return sanitizeErrorCode(value)
	case map[string]any:
		if code, ok := value["code"].(string); ok && code != "" {
			return sanitizeErrorCode(code)
		}
	}
	return "unknown_error"
}

func sanitizeErrorCode(code string) string {
	if code == "" || len(code) > 64 {
		return "unknown_error"
	}
	for _, char := range code {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != '_' && char != '-' && char != '.' {
			return "unknown_error"
		}
	}
	return code
}
