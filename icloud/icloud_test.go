package icloud_test

import (
	"math/big"
	"testing"

	"github.com/bodgit/srp/icloud"
	"github.com/bodgit/srp/internal/rfc5054"
	"github.com/bodgit/srp/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestGetGroup(t *testing.T) {
	t.Parallel()

	tables := []struct {
		group int
		err   error
	}{
		{
			2048,
			nil,
		},
		{
			23,
			util.ErrGroupNotFound,
		},
	}

	for _, table := range tables {
		_, err := icloud.GetGroup(table.group)

		if table.err != nil && assert.Error(t, err) {
			assert.ErrorIs(t, err, table.err)
		}
	}
}

func TestNewSRP(t *testing.T) {
	t.Parallel()

	s := util.Must(icloud.NewSRP())

	assert.Equal(t, 256, s.Group().Size)
	assert.Equal(t, 32, len(s.HashBytes([]byte("test"))))
}

func TestComputeX(t *testing.T) {
	t.Parallel()

	s := util.Must(icloud.NewSRP())
	x := icloud.ComputeX(s, rfc5054.Identity, rfc5054.Password, rfc5054.Salt)
	want := s.HashInt(rfc5054.Salt, s.HashBytes([]byte(":"), rfc5054.Password))
	xDifferentIdentity := icloud.ComputeX(s, []byte("bob"), rfc5054.Password, rfc5054.Salt)

	assert.Equal(t, want.Bytes(), x.Bytes())
	assert.Equal(t, x.Bytes(), xDifferentIdentity.Bytes())
}

func TestComputeM1(t *testing.T) {
	t.Parallel()

	s := util.Must(icloud.NewSRP())
	xA := new(big.Int).SetBytes(rfc5054.XA)
	xB := new(big.Int).SetBytes(rfc5054.XB)
	xK := s.HashBytes(rfc5054.PremasterSecret)
	want := util.Must(util.BytesFromHexString(`
		6E89D09A 111556B7 54024208 EC8DA594 183BDAA5 3DBB4732 4C39B1A9
		8474671B`))

	assert.Equal(t, want, icloud.ComputeM1(s, xA, xB, xK, rfc5054.Identity, rfc5054.Salt))
}
