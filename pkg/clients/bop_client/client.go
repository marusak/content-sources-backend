package bop_client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/content-services/content-sources-backend/pkg/config"
)

const defaultSender = `"Lightwell" noreply@redhat.com`

// Client calls the Back Office Proxy to resolve usernames and send email.
type Client struct {
	server   string
	apiToken string
	clientID string
	env      string
	sender   string
	http     *http.Client
}

func New(cfg config.BOP) (*Client, error) {
	server := strings.TrimRight(strings.TrimSpace(cfg.Server), "/")
	if server == "" {
		return nil, fmt.Errorf("clients.bop.server is not set")
	}
	sender := cfg.Sender
	if sender == "" {
		sender = defaultSender
	}
	return &Client{
		server:   server,
		apiToken: cfg.APIToken,
		clientID: cfg.ClientID,
		env:      cfg.Env,
		sender:   sender,
		http:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

type bopUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

// EmailsByUsername returns a lower-cased username to email address map for the
// usernames BOP knows. Usernames with no email are omitted.
func (c *Client) EmailsByUsername(ctx context.Context, usernames []string) (map[string]string, error) {
	body, err := json.Marshal(map[string][]string{"users": usernames})
	if err != nil {
		return nil, err
	}
	payload, err := c.post(ctx, "/v1/users", body)
	if err != nil {
		return nil, err
	}
	users, err := decodeBOPUsers(payload)
	if err != nil {
		return nil, err
	}
	emails := make(map[string]string, len(users))
	for _, user := range users {
		username := strings.ToLower(strings.TrimSpace(user.Username))
		email := strings.TrimSpace(user.Email)
		if username == "" || email == "" {
			continue
		}
		if _, ok := emails[username]; !ok {
			emails[username] = email
		}
	}
	return emails, nil
}

func decodeBOPUsers(payload []byte) ([]bopUser, error) {
	var listed []bopUser
	if err := json.Unmarshal(payload, &listed); err == nil {
		return listed, nil
	}
	var wrapped struct {
		Users []bopUser `json:"users"`
	}
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return nil, fmt.Errorf("parse BOP users response: %w", err)
	}
	return wrapped.Users, nil
}

// SendEmail sends one message with every address on the To line.
func (c *Client) SendEmail(ctx context.Context, to []string, subject, body string) error {
	payload, err := json.Marshal(map[string]any{
		"emails": []map[string]any{{
			"subject":    subject,
			"body":       body,
			"recipients": to,
			"bodyType":   "text",
		}},
		"skipUsersResolution": true,
		"emailSender":         c.sender,
		"defaultRecipient":    c.sender,
	})
	if err != nil {
		return err
	}
	_, err = c.post(ctx, "/v1/sendEmails", payload)
	return err
}

func (c *Client) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-rh-apitoken", c.apiToken)
	req.Header.Set("x-rh-clientid", c.clientID)
	req.Header.Set("x-rh-insights-env", c.env)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("BOP %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("BOP %s: read response: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("BOP %s: status %d", path, resp.StatusCode)
	}
	return respBody, nil
}
