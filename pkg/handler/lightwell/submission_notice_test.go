package lightwell

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

func TestSubmissionNoticeForTAMs(t *testing.T) {
	notice, missing := submissionNotice("CID-00000", []string{"bob", "ann"}, map[string]string{
		"ann": "ann@redhat.com",
		"bob": "bob@redhat.com",
	}, []string{"fallback@redhat.com"})
	assert.Equal(t, []string{"ann@redhat.com", "bob@redhat.com"}, notice.to)
	assert.Equal(t, "New submission for CID-00000 created.", notice.subject)
	assert.Equal(t, submissionReviewLine, notice.body)
	assert.Empty(t, missing)
}

func TestSubmissionNoticeMissingEmail(t *testing.T) {
	notice, missing := submissionNotice("CID-00000", []string{"ann", "bob"}, map[string]string{
		"ann": "ann@redhat.com",
	}, nil)
	assert.Equal(t, []string{"ann@redhat.com"}, notice.to)
	assert.Equal(t, []string{"bob"}, missing)
}

func TestSubmissionNoticeWithoutTAM(t *testing.T) {
	notice, missing := submissionNotice("CID-00042", nil, nil, []string{"ops@redhat.com", "oncall@redhat.com"})
	assert.Equal(t, []string{"ops@redhat.com", "oncall@redhat.com"}, notice.to)
	assert.Equal(t, "New submission created for CID-00042 that does not have TAM assigned", notice.subject)
	assert.Equal(t, submissionReviewLine+"\nSet up TAM for CID-00042", notice.body)
	assert.Empty(t, missing)
}

func TestNotifySubmittedClearinghouse(t *testing.T) {
	var usersBody map[string][]string
	var sent map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		switch r.URL.Path {
		case "/v1/users":
			require.NoError(t, json.Unmarshal(body, &usersBody))
			_, _ = w.Write([]byte(`[{"username":"ann","email":"ann@redhat.com"},{"username":"bob","email":"bob@redhat.com"}]`))
		case "/v1/sendEmails":
			require.NoError(t, json.Unmarshal(body, &sent))
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	saved := config.Get().Clients
	t.Cleanup(func() { config.Get().Clients = saved })
	config.Get().Clients.Lightwell.ClearinghouseMapping = config.ParseClearinghouseMappings(
		`{"CidOrgId":{"CID-00000":"org-1"},"CidTam":{"CID-00000":["bob","ann"]}}`,
	)
	config.Get().Clients.Lightwell.DefaultTamEmails = `["fallback@redhat.com"]`
	config.Get().Clients.BOP = config.BOP{Server: server.URL, APIToken: "token", ClientID: "client", Env: "prod"}

	require.NoError(t, notifySubmittedClearinghouse(context.Background(), "org-1"))
	assert.ElementsMatch(t, []string{"ann", "bob"}, usersBody["users"])
	emails := sent["emails"].([]any)
	message := emails[0].(map[string]any)
	assert.Equal(t, "New submission for CID-00000 created.", message["subject"])
	assert.Equal(t, submissionReviewLine, message["body"])
	assert.ElementsMatch(t, []any{"ann@redhat.com", "bob@redhat.com"}, message["recipients"])
}

func TestNotifySubmittedClearinghouseWithoutTAM(t *testing.T) {
	var sent map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/sendEmails", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&sent))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	saved := config.Get().Clients
	t.Cleanup(func() { config.Get().Clients = saved })
	config.Get().Clients.Lightwell.ClearinghouseMapping = config.ParseClearinghouseMappings(
		`{"CidOrgId":{"CID-00042":"org-1"},"CidTam":{"CID-00042":[]}}`,
	)
	config.Get().Clients.Lightwell.DefaultTamEmails = `["ops@redhat.com"]`
	config.Get().Clients.BOP = config.BOP{Server: server.URL}

	require.NoError(t, notifySubmittedClearinghouse(context.Background(), "org-1"))
	emails := sent["emails"].([]any)
	message := emails[0].(map[string]any)
	assert.Equal(t, "New submission created for CID-00042 that does not have TAM assigned", message["subject"])
	assert.Equal(t, submissionReviewLine+"\nSet up TAM for CID-00042", message["body"])
	assert.Equal(t, []any{"ops@redhat.com"}, message["recipients"])
}
