package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/content-services/content-sources-backend/pkg/api"
	"github.com/content-services/content-sources-backend/pkg/config"
	"github.com/content-services/content-sources-backend/pkg/middleware"
	"github.com/labstack/echo/v4"
	"github.com/redhatinsights/platform-go-middlewares/v2/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type FeaturesSuite struct {
	suite.Suite
	oldFeatureSet config.FeatureSet
}

func TestFeaturesSuite(t *testing.T) {
	suite.Run(t, new(FeaturesSuite))
}
func (s *FeaturesSuite) SetupTest() {
	// Backup previous config
	s.oldFeatureSet = config.Get().Features
}
func (s *FeaturesSuite) TearDownTest() {
	// Restore previous config
	config.Get().Features = s.oldFeatureSet
}

func serveFeaturesRouter(req *http.Request) (int, []byte, error) {
	router := echo.New()
	router.HTTPErrorHandler = config.CustomHTTPErrorHandler
	router.Use(middleware.WrapMiddlewareWithSkipper(identity.EnforceIdentity, middleware.SkipAuth))
	pathPrefix := router.Group(api.FullRootPath())

	RegisterFeaturesRoutes(pathPrefix)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	response := rr.Result()
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	return response.StatusCode, body, err
}

type FeatureTestCase struct {
	name           string
	id             identity.Identity
	allowedAccount *string
	allowedUser    *string
	allowedOrg     *string
	expected       api.FeatureSet
}

func TestFeatures(t *testing.T) {
	config.Get().Features.Snapshots.Enabled = true
	config.Get().Features.AdminTasks.Enabled = true
	defer resetFeatures()

	path := fmt.Sprintf("%s/features/", api.FullRootPath())
	req, _ := http.NewRequest("GET", path, nil)
	user := identity.Identity{
		Type:          "User",
		AccountNumber: "acct",
		OrgID:         "orgId",
		Internal: identity.Internal{
			OrgID: "orgId",
		},
		User: &identity.User{Username: "foo"}}

	testCases := []FeatureTestCase{
		{
			name:        "Allowed with Username",
			id:          user,
			allowedUser: &user.User.Username,
			expected: api.FeatureSet{
				"snapshots": {
					Enabled:    true,
					Accessible: true,
				},
				"admintasks": {
					Enabled:    true,
					Accessible: true,
				}},
		},
		{
			name:           "Allowed with Account",
			id:             user,
			allowedAccount: &user.AccountNumber,
			expected: api.FeatureSet{
				"snapshots": {
					Enabled:    true,
					Accessible: true,
				},
				"admintasks": {
					Enabled:    true,
					Accessible: true,
				}},
		},
		{
			name:       "Allowed with OrgId",
			id:         user,
			allowedOrg: &user.OrgID,
			expected: api.FeatureSet{
				"snapshots": {
					Enabled:    true,
					Accessible: true,
				},
				"admintasks": {
					Enabled:    true,
					Accessible: true,
				}},
		},
		{
			name: "Not allowed ",
			id:   user,
			expected: api.FeatureSet{
				"snapshots": {
					Enabled:    true,
					Accessible: false,
				},
				"admintasks": {
					Enabled:    true,
					Accessible: false,
				}},
		},
	}

	for _, testcase := range testCases {
		config.Get().Features.Snapshots.Users = &[]string{}
		config.Get().Features.Snapshots.Accounts = &[]string{}
		config.Get().Features.Snapshots.Organizations = &[]string{}

		if testcase.allowedUser != nil {
			config.Get().Features.Snapshots.Users = &[]string{*testcase.allowedUser}
		}
		if testcase.allowedAccount != nil {
			config.Get().Features.Snapshots.Accounts = &[]string{*testcase.allowedAccount}
		}
		if testcase.allowedOrg != nil {
			config.Get().Features.Snapshots.Organizations = &[]string{*testcase.allowedOrg}
		}

		config.Get().Features.AdminTasks.Users = &[]string{}
		config.Get().Features.AdminTasks.Accounts = &[]string{}
		config.Get().Features.AdminTasks.Organizations = &[]string{}

		if testcase.allowedUser != nil {
			config.Get().Features.AdminTasks.Users = &[]string{*testcase.allowedUser}
		}
		if testcase.allowedAccount != nil {
			config.Get().Features.AdminTasks.Accounts = &[]string{*testcase.allowedAccount}
		}
		if testcase.allowedOrg != nil {
			config.Get().Features.AdminTasks.Organizations = &[]string{*testcase.allowedOrg}
		}

		newReq := wrapReqWithIdentity(t, req, testcase.id)
		code, body, err := serveFeaturesRouter(newReq)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, code)
		var featureResponse api.FeatureSet
		err = json.Unmarshal(body, &featureResponse)
		assert.NoError(t, err, "Could not marshal response for testcase %v", testcase.name)

		for k, v := range testcase.expected {
			assert.Equal(t, v, featureResponse[k], "Expected response for %v does not match key %v", testcase.name, k)
		}
	}
}

func wrapReqWithIdentity(t *testing.T, req *http.Request, id identity.Identity) *http.Request {
	json, err := json.Marshal(identity.XRHID{Identity: id})
	assert.NoError(t, err)
	base64Str := base64.StdEncoding.EncodeToString([]byte(string(json)))

	req.Header.Set("X-Rh-Identity", base64Str)
	return req
}
