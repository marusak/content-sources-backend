package store_test

import (
	"testing"

	"github.com/content-services/content-sources-backend/pkg/lightwell/db/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClearinghouseUploadList(t *testing.T) {
	ctx, tx, queries := beginTestTx(t)
	t.Cleanup(func() { rollbackTestTx(t, tx) })

	orgA := "org-a"
	orgB := "org-b"
	first, err := queries.CreateClearinghouseUpload(ctx, store.CreateClearinghouseUploadParams{
		Uuid:   uuid.New(),
		OrgID:  orgA,
		Status: "validating",
	})
	require.NoError(t, err)
	_, err = queries.CreateClearinghouseUploadFile(ctx, store.CreateClearinghouseUploadFileParams{
		Uuid:                    uuid.New(),
		ClearinghouseUploadUuid: first.Uuid,
		Filename:                "vulnerabilities.json",
		Filepath:                "uploads/" + first.Uuid.String() + "/vulnerabilities.json",
	})
	require.NoError(t, err)
	_, err = queries.CreateClearinghouseUpload(ctx, store.CreateClearinghouseUploadParams{
		Uuid:   uuid.New(),
		OrgID:  orgB,
		Status: "submitted",
	})
	require.NoError(t, err)

	listed, err := queries.ListClearinghouseUploads(ctx, store.ListClearinghouseUploadsParams{
		OrgID:     &orgA,
		PageLimit: 10,
	})
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, first.Uuid, listed[0].Uuid)

	count, err := queries.CountClearinghouseUploads(ctx, &orgA)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	files, err := queries.ListClearinghouseUploadFilesByUploads(ctx, []uuid.UUID{first.Uuid})
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "vulnerabilities.json", files[0].Filename)

	allCount, err := queries.CountClearinghouseUploads(ctx, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, allCount, int64(2))
}
