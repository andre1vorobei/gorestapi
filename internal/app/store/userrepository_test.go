package store_test

import (
	"gorestapi/internal/app/model"
	"gorestapi/internal/app/store"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserRepository_Create(t *testing.T) {
	s, teardown := store.TestStore(t, databaseURL)
	defer teardown("users")

	u, err := s.User().Create(model.TestUser(t))
	assert.NoError(t, err)
	assert.NotNil(t, u)
}

func TestUserRepository_Find(t *testing.T) {
	s, teardown := store.TestStore(t, databaseURL)
	defer teardown("users")

	//
	u, err := s.User().Create(model.TestUser(t))

	_, err = s.User().FindByEmail(u.Email)
	assert.NoError(t, err)
	_, err = s.User().FindByUsername(u.UserName)
	assert.NoError(t, err)
}
