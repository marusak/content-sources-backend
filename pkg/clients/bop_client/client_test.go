package bop_client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/content-services/content-sources-backend/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailsByUsername(t *testing.T) {
	var gotBody map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/users", r.URL.Path)
		assert.Equal(t, "token", r.Header.Get("x-rh-apitoken"))
		assert.Equal(t, "client", r.Header.Get("x-rh-clientid"))
		assert.Equal(t, "stage", r.Header.Get("x-rh-insights-env"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"userCount":2,"users":[{"username":"Ann","email":"ann@redhat.com"},{"username":"bob","email":"bob@redhat.com"},{"username":"bob","email":"other@redhat.com"}]}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(config.BOP{Server: server.URL + "/", APIToken: "token", ClientID: "client", Env: "stage"})
	require.NoError(t, err)
	emails, err := client.EmailsByUsername(context.Background(), []string{"ann", "bob"})
	require.NoError(t, err)
	assert.Equal(t, []string{"ann", "bob"}, gotBody["users"])
	assert.Equal(t, map[string]string{"ann": "ann@redhat.com", "bob": "bob@redhat.com"}, emails)
}

func TestEmailsByUsernameListResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"username":"ann","email":"ann@redhat.com"}]`))
	}))
	t.Cleanup(server.Close)

	client, err := New(config.BOP{Server: server.URL})
	require.NoError(t, err)
	emails, err := client.EmailsByUsername(context.Background(), []string{"ann"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"ann": "ann@redhat.com"}, emails)
}

func TestSendEmailPutsRecipientsOnTo(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/sendEmails", r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &got))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client, err := New(config.BOP{Server: server.URL, Sender: "Lightwell <noreply@redhat.com>"})
	require.NoError(t, err)
	require.NoError(t, client.SendEmail(context.Background(), []string{"a@redhat.com", "b@redhat.com"}, "subject", "body"))

	assert.Equal(t, true, got["skipUsersResolution"])
	assert.Equal(t, "Lightwell <noreply@redhat.com>", got["emailSender"])
	emails := got["emails"].([]any)
	require.Len(t, emails, 1)
	message := emails[0].(map[string]any)
	assert.Equal(t, "subject", message["subject"])
	assert.Equal(t, "body", message["body"])
	assert.Equal(t, "text", message["bodyType"])
	assert.Equal(t, []any{"a@redhat.com", "b@redhat.com"}, message["recipients"])
	_, hasBCC := message["bccList"]
	assert.False(t, hasBCC)
}

func TestNewRequiresServer(t *testing.T) {
	_, err := New(config.BOP{})
	require.Error(t, err)
}
