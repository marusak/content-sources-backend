// Code generated by mockery v2.35.4. DO NOT EDIT.

package dao

import (
	context "context"

	api "github.com/content-services/content-sources-backend/pkg/api"

	mock "github.com/stretchr/testify/mock"

	yum "github.com/content-services/yummy/pkg/yum"
)

// MockRpmDao is an autogenerated mock type for the RpmDao type
type MockRpmDao struct {
	mock.Mock
}

// DetectRpms provides a mock function with given fields: orgID, request
func (_m *MockRpmDao) DetectRpms(orgID string, request api.DetectRpmsRequest) (*api.DetectRpmsResponse, error) {
	ret := _m.Called(orgID, request)

	var r0 *api.DetectRpmsResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(string, api.DetectRpmsRequest) (*api.DetectRpmsResponse, error)); ok {
		return rf(orgID, request)
	}
	if rf, ok := ret.Get(0).(func(string, api.DetectRpmsRequest) *api.DetectRpmsResponse); ok {
		r0 = rf(orgID, request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*api.DetectRpmsResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(string, api.DetectRpmsRequest) error); ok {
		r1 = rf(orgID, request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertForRepository provides a mock function with given fields: repoUuid, pkgs
func (_m *MockRpmDao) InsertForRepository(repoUuid string, pkgs []yum.Package) (int64, error) {
	ret := _m.Called(repoUuid, pkgs)

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func(string, []yum.Package) (int64, error)); ok {
		return rf(repoUuid, pkgs)
	}
	if rf, ok := ret.Get(0).(func(string, []yum.Package) int64); ok {
		r0 = rf(repoUuid, pkgs)
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func(string, []yum.Package) error); ok {
		r1 = rf(repoUuid, pkgs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// List provides a mock function with given fields: orgID, uuidRepo, limit, offset, search, sortBy
func (_m *MockRpmDao) List(orgID string, uuidRepo string, limit int, offset int, search string, sortBy string) (api.RepositoryRpmCollectionResponse, int64, error) {
	ret := _m.Called(orgID, uuidRepo, limit, offset, search, sortBy)

	var r0 api.RepositoryRpmCollectionResponse
	var r1 int64
	var r2 error
	if rf, ok := ret.Get(0).(func(string, string, int, int, string, string) (api.RepositoryRpmCollectionResponse, int64, error)); ok {
		return rf(orgID, uuidRepo, limit, offset, search, sortBy)
	}
	if rf, ok := ret.Get(0).(func(string, string, int, int, string, string) api.RepositoryRpmCollectionResponse); ok {
		r0 = rf(orgID, uuidRepo, limit, offset, search, sortBy)
	} else {
		r0 = ret.Get(0).(api.RepositoryRpmCollectionResponse)
	}

	if rf, ok := ret.Get(1).(func(string, string, int, int, string, string) int64); ok {
		r1 = rf(orgID, uuidRepo, limit, offset, search, sortBy)
	} else {
		r1 = ret.Get(1).(int64)
	}

	if rf, ok := ret.Get(2).(func(string, string, int, int, string, string) error); ok {
		r2 = rf(orgID, uuidRepo, limit, offset, search, sortBy)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// ListSnapshotRpms provides a mock function with given fields: ctx, orgId, snapshotUUIDs, search, pageOpts
func (_m *MockRpmDao) ListSnapshotRpms(ctx context.Context, orgId string, snapshotUUIDs []string, search string, pageOpts api.PaginationData) ([]api.SnapshotRpm, int, error) {
	ret := _m.Called(ctx, orgId, snapshotUUIDs, search, pageOpts)

	var r0 []api.SnapshotRpm
	var r1 int
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []string, string, api.PaginationData) ([]api.SnapshotRpm, int, error)); ok {
		return rf(ctx, orgId, snapshotUUIDs, search, pageOpts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, []string, string, api.PaginationData) []api.SnapshotRpm); ok {
		r0 = rf(ctx, orgId, snapshotUUIDs, search, pageOpts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]api.SnapshotRpm)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, []string, string, api.PaginationData) int); ok {
		r1 = rf(ctx, orgId, snapshotUUIDs, search, pageOpts)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, []string, string, api.PaginationData) error); ok {
		r2 = rf(ctx, orgId, snapshotUUIDs, search, pageOpts)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// OrphanCleanup provides a mock function with given fields:
func (_m *MockRpmDao) OrphanCleanup() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Search provides a mock function with given fields: orgID, request
func (_m *MockRpmDao) Search(orgID string, request api.ContentUnitSearchRequest) ([]api.SearchRpmResponse, error) {
	ret := _m.Called(orgID, request)

	var r0 []api.SearchRpmResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(string, api.ContentUnitSearchRequest) ([]api.SearchRpmResponse, error)); ok {
		return rf(orgID, request)
	}
	if rf, ok := ret.Get(0).(func(string, api.ContentUnitSearchRequest) []api.SearchRpmResponse); ok {
		r0 = rf(orgID, request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]api.SearchRpmResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(string, api.ContentUnitSearchRequest) error); ok {
		r1 = rf(orgID, request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SearchSnapshotRpms provides a mock function with given fields: ctx, orgId, request
func (_m *MockRpmDao) SearchSnapshotRpms(ctx context.Context, orgId string, request api.SnapshotSearchRpmRequest) ([]api.SearchRpmResponse, error) {
	ret := _m.Called(ctx, orgId, request)

	var r0 []api.SearchRpmResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, api.SnapshotSearchRpmRequest) ([]api.SearchRpmResponse, error)); ok {
		return rf(ctx, orgId, request)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, api.SnapshotSearchRpmRequest) []api.SearchRpmResponse); ok {
		r0 = rf(ctx, orgId, request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]api.SearchRpmResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, api.SnapshotSearchRpmRequest) error); ok {
		r1 = rf(ctx, orgId, request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewMockRpmDao creates a new instance of MockRpmDao. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockRpmDao(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockRpmDao {
	mock := &MockRpmDao{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
