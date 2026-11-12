package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEmailList(t *testing.T) {
	emails, err := ParseEmailList(`["a@redhat.com", " b@redhat.com ", ""]`)
	require.NoError(t, err)
	assert.Equal(t, []string{"a@redhat.com", "b@redhat.com"}, emails)

	emails, err = ParseEmailList("")
	require.NoError(t, err)
	assert.Empty(t, emails)

	emails, err = ParseEmailList("[]")
	require.NoError(t, err)
	assert.Empty(t, emails)

	_, err = ParseEmailList("a@redhat.com")
	require.Error(t, err)
}
