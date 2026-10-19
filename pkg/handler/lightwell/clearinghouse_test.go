package lightwell

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/content-services/content-sources-backend/pkg/api"
	"github.com/content-services/content-sources-backend/pkg/clients/s3_client"
	"github.com/content-services/content-sources-backend/pkg/config"
	"github.com/content-services/content-sources-backend/pkg/lightwell/db/store"
	"github.com/content-services/content-sources-backend/pkg/middleware"
	test_handler "github.com/content-services/content-sources-backend/pkg/test/handler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	"github.com/redhatinsights/platform-go-middlewares/v2/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestClearinghouseSubmissions(t *testing.T) {
	oldClearinghouse := config.Get().Features.LightwellClearinghouse
	oldRead := config.Get().Features.LightwellClearinghouseRead
	t.Cleanup(func() {
		config.Get().Features.LightwellClearinghouse = oldClearinghouse
		config.Get().Features.LightwellClearinghouseRead = oldRead
	})

	uploads := &memClearinghouseStore{}
	s3Client := s3_client.NewMockS3Client(t)
	s3Client.On("Put", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)

	config.Get().Features.LightwellClearinghouse = config.Feature{Enabled: false}
	config.Get().Features.LightwellClearinghouseRead = config.Feature{Enabled: false}

	code, body := serveClearinghouse(t, uploads, s3Client, clearinghouseUploadRequest(t, http.MethodPost, "/clearinghouse/submissions", "file", map[string]string{
		"vulnerabilities.json": `{"vulnerabilities":[]}`,
	}))
	assert.Equal(t, http.StatusBadRequest, code, string(body))

	config.Get().Features.LightwellClearinghouse = config.Feature{Enabled: true}
	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseUploadRequest(t, http.MethodPost, "/clearinghouse/submissions", "file", map[string]string{
		strings.Repeat("a", 300) + ".json": "nope",
	}))
	assert.Equal(t, http.StatusBadRequest, code, string(body))

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseUploadRequest(t, http.MethodPost, "/clearinghouse/submissions", "file", map[string]string{
		"vulnerabilities.json": `{"vulnerabilities":[]}`,
		"reproducer.py":        "print('hi')",
	}))
	assert.Equal(t, http.StatusBadRequest, code, string(body))

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseUploadRequest(t, http.MethodPost, "/clearinghouse/submissions", "file", map[string]string{
		"vulnerabilities.json": `{"vulnerabilities":[]}`,
	}))
	require.Equal(t, http.StatusCreated, code, string(body))
	var created api.ClearinghouseSubmission
	require.NoError(t, json.Unmarshal(body, &created))
	assert.Equal(t, api.ClearinghouseSubmissionStatusValidating, created.Status)
	assert.Equal(t, test_handler.MockOrgId, created.OrgID)
	require.Len(t, created.Files, 1)
	assert.Equal(t, "vulnerabilities.json", created.Files[0].Filename)

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseUploadRequest(t, http.MethodPost, "/clearinghouse/submissions/"+created.UUID+"/files", "files", map[string]string{
		"reproducer.py": "print('hi')",
	}))
	require.Equal(t, http.StatusOK, code, string(body))

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseUploadRequest(t, http.MethodPost, "/clearinghouse/submissions/"+created.UUID+"/files", "files", map[string]string{
		"notes.txt": "more",
	}))
	require.Equal(t, http.StatusOK, code, string(body))
	var updated api.ClearinghouseSubmission
	require.NoError(t, json.Unmarshal(body, &updated))
	assert.Len(t, updated.Files, 3)

	otherUser := test_handler.MockIdentity
	otherUser.Identity.AccountNumber = "other-account"
	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseUploadRequestAs(t, http.MethodPost, "/clearinghouse/submissions/"+created.UUID+"/files", "files", map[string]string{
		"other.txt": "nope",
	}, otherUser))
	assert.Equal(t, http.StatusForbidden, code, string(body))

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseUploadRequest(t, http.MethodPost, "/clearinghouse/submissions/"+created.UUID+"/files", "files", map[string]string{
		"notes.txt": "again",
	}))
	assert.Equal(t, http.StatusConflict, code, string(body))

	otherID := uuid.New()
	uploads.uploads = append(uploads.uploads, store.ClearinghouseUpload{
		Uuid:   otherID,
		OrgID:  "other-org",
		Status: api.ClearinghouseSubmissionStatusSubmitted,
	})

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseRequest(t, http.MethodGet, "/clearinghouse/submissions"))
	require.Equal(t, http.StatusOK, code, string(body))
	var listed api.ClearinghouseSubmissionCollectionResponse
	require.NoError(t, json.Unmarshal(body, &listed))
	require.Len(t, listed.Data, 1)
	assert.Equal(t, created.UUID, listed.Data[0].UUID)
	assert.Len(t, listed.Data[0].Files, 3)

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseRequest(t, http.MethodGet, "/clearinghouse/submissions/"+created.UUID))
	require.Equal(t, http.StatusOK, code, string(body))
	var fetched api.ClearinghouseSubmission
	require.NoError(t, json.Unmarshal(body, &fetched))
	assert.Equal(t, created.UUID, fetched.UUID)
	assert.Equal(t, api.ClearinghouseSubmissionStatusValidating, fetched.Status)
	assert.Len(t, fetched.Files, 3)

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseRequest(t, http.MethodGet, "/clearinghouse/submissions/"+otherID.String()))
	assert.Equal(t, http.StatusNotFound, code, string(body))

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseRequest(t, http.MethodGet, "/clearinghouse/submissions/"+created.UUID+"/files/reproducer.py"))
	assert.Equal(t, http.StatusBadRequest, code, string(body))

	config.Get().Features.LightwellClearinghouseRead = config.Feature{Enabled: true}
	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseRequest(t, http.MethodGet, "/clearinghouse/submissions"))
	require.Equal(t, http.StatusOK, code, string(body))
	require.NoError(t, json.Unmarshal(body, &listed))
	assert.Len(t, listed.Data, 2)

	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseRequest(t, http.MethodGet, "/clearinghouse/submissions/"+otherID.String()))
	require.Equal(t, http.StatusOK, code, string(body))
	require.NoError(t, json.Unmarshal(body, &fetched))
	assert.Equal(t, otherID.String(), fetched.UUID)
	assert.Equal(t, api.ClearinghouseSubmissionStatusSubmitted, fetched.Status)

	s3Client.On("Get", mock.Anything, "uploads/"+created.UUID+"/reproducer.py").Return(io.NopCloser(strings.NewReader("print('hi')")), nil)
	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseRequest(t, http.MethodGet, "/clearinghouse/submissions/"+created.UUID+"/files/reproducer.py"))
	require.Equal(t, http.StatusOK, code, string(body))
	assert.Equal(t, "print('hi')", string(body))

	config.Get().Features.LightwellClearinghouse = config.Feature{Enabled: false}
	code, body = serveClearinghouse(t, uploads, s3Client, clearinghouseUploadRequest(t, http.MethodPost, "/clearinghouse/submissions", "file", map[string]string{
		"another.txt": "no",
	}))
	assert.Equal(t, http.StatusBadRequest, code, string(body))
}

type memClearinghouseStore struct {
	uploads []store.ClearinghouseUpload
	files   []store.ClearinghouseUploadFile
}

func (m *memClearinghouseStore) CreateClearinghouseUpload(_ context.Context, arg store.CreateClearinghouseUploadParams) (store.ClearinghouseUpload, error) {
	row := store.ClearinghouseUpload{
		Uuid:               arg.Uuid,
		OrgID:              arg.OrgID,
		AccountID:          arg.AccountID,
		VulnerabilityCount: arg.VulnerabilityCount,
		Status:             arg.Status,
		ErrorMessage:       arg.ErrorMessage,
	}
	m.uploads = append(m.uploads, row)
	return row, nil
}

func (m *memClearinghouseStore) GetClearinghouseUpload(_ context.Context, uploadID uuid.UUID) (store.ClearinghouseUpload, error) {
	for _, upload := range m.uploads {
		if upload.Uuid == uploadID {
			return upload, nil
		}
	}
	return store.ClearinghouseUpload{}, pgx.ErrNoRows
}

func (m *memClearinghouseStore) CreateClearinghouseUploadFile(_ context.Context, arg store.CreateClearinghouseUploadFileParams) (store.ClearinghouseUploadFile, error) {
	for _, file := range m.files {
		if file.ClearinghouseUploadUuid == arg.ClearinghouseUploadUuid && file.Filename == arg.Filename {
			return store.ClearinghouseUploadFile{}, &pgconn.PgError{Code: "23505"}
		}
	}
	row := store.ClearinghouseUploadFile{
		Uuid:                    arg.Uuid,
		ClearinghouseUploadUuid: arg.ClearinghouseUploadUuid,
		Filename:                arg.Filename,
		Filepath:                arg.Filepath,
	}
	m.files = append(m.files, row)
	return row, nil
}

func (m *memClearinghouseStore) ListClearinghouseUploadFiles(_ context.Context, clearinghouseUploadUuid uuid.UUID) ([]store.ClearinghouseUploadFile, error) {
	return m.ListClearinghouseUploadFilesByUploads(context.Background(), []uuid.UUID{clearinghouseUploadUuid})
}

func (m *memClearinghouseStore) ListClearinghouseUploads(_ context.Context, arg store.ListClearinghouseUploadsParams) ([]store.ClearinghouseUpload, error) {
	matched := make([]store.ClearinghouseUpload, 0)
	for _, upload := range m.uploads {
		if arg.OrgID == nil || upload.OrgID == *arg.OrgID {
			matched = append(matched, upload)
		}
	}
	slices.SortFunc(matched, func(a, b store.ClearinghouseUpload) int {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return strings.Compare(b.Uuid.String(), a.Uuid.String())
		}
		if a.CreatedAt.Before(b.CreatedAt) {
			return 1
		}
		return -1
	})
	start := int(arg.PageOffset)
	if start > len(matched) {
		return []store.ClearinghouseUpload{}, nil
	}
	end := start + int(arg.PageLimit)
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], nil
}

func (m *memClearinghouseStore) CountClearinghouseUploads(_ context.Context, orgID *string) (int64, error) {
	var count int64
	for _, upload := range m.uploads {
		if orgID == nil || upload.OrgID == *orgID {
			count++
		}
	}
	return count, nil
}

func (m *memClearinghouseStore) ListClearinghouseUploadFilesByUploads(_ context.Context, uploadUuids []uuid.UUID) ([]store.ClearinghouseUploadFile, error) {
	wanted := map[uuid.UUID]struct{}{}
	for _, id := range uploadUuids {
		wanted[id] = struct{}{}
	}
	matched := make([]store.ClearinghouseUploadFile, 0)
	for _, file := range m.files {
		if _, ok := wanted[file.ClearinghouseUploadUuid]; ok {
			matched = append(matched, file)
		}
	}
	slices.SortFunc(matched, func(a, b store.ClearinghouseUploadFile) int {
		if a.ClearinghouseUploadUuid != b.ClearinghouseUploadUuid {
			return strings.Compare(a.ClearinghouseUploadUuid.String(), b.ClearinghouseUploadUuid.String())
		}
		return strings.Compare(a.Filename, b.Filename)
	})
	return matched, nil
}

func (m *memClearinghouseStore) GetClearinghouseUploadFileByName(_ context.Context, arg store.GetClearinghouseUploadFileByNameParams) (store.ClearinghouseUploadFile, error) {
	for _, file := range m.files {
		if file.ClearinghouseUploadUuid == arg.ClearinghouseUploadUuid && file.Filename == arg.Filename {
			return file, nil
		}
	}
	return store.ClearinghouseUploadFile{}, pgx.ErrNoRows
}

func serveClearinghouse(t *testing.T, uploads clearinghouseUploadStore, s3Client s3_client.S3Client, req *http.Request) (int, []byte) {
	t.Helper()
	router := echo.New()
	router.Use(middleware.WrapMiddlewareWithSkipper(identity.EnforceIdentity, middleware.SkipMiddleware))
	router.HTTPErrorHandler = config.CustomHTTPErrorHandler
	RegisterClearinghouseRoutes(router.Group(LightwellAPIPath), uploads, s3Client)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	body, err := io.ReadAll(rr.Result().Body)
	require.NoError(t, err)
	return rr.Code, body
}

func clearinghouseRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, LightwellAPIPath+path, nil)
	req.Header.Set(api.IdentityHeader, test_handler.EncodedIdentity(t))
	return req
}

func clearinghouseUploadRequest(t *testing.T, method, path, field string, files map[string]string) *http.Request {
	t.Helper()
	return clearinghouseUploadRequestAs(t, method, path, field, files, test_handler.MockIdentity)
}

func clearinghouseUploadRequestAs(t *testing.T, method, path, field string, files map[string]string, id identity.XRHID) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	for name, content := range files {
		part, err := writer.CreateFormFile(field, name)
		require.NoError(t, err)
		_, err = part.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	req := httptest.NewRequest(method, LightwellAPIPath+path, &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set(api.IdentityHeader, test_handler.EncodedCustomIdentity(t, id))
	return req
}
