package smolmailer

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveParallelSuccess(t *testing.T) {
	fabFail := func(delay time.Duration) func() (io.Closer, error) {
		return func() (io.Closer, error) {
			time.Sleep(delay)
			return nil, errors.New("failed after sleep")
		}
	}

	fSuccess := func() (io.Closer, error) {
		time.Sleep(time.Millisecond * 300)
		return io.NopCloser(nil), nil
	}

	ff1 := fabFail(time.Millisecond * 100)
	ff2 := fabFail(time.Millisecond * 200)
	ff3 := fabFail(time.Millisecond * 400)

	start := time.Now()
	res, err := resolveParallel(ff1, fSuccess, ff2, ff3)
	stop := time.Now()
	runDuration := stop.Sub(start)
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.LessOrEqual(t, time.Millisecond*300, runDuration)
	assert.Less(t, runDuration, time.Millisecond*400)
}

func TestResolveParallelFail(t *testing.T) {
	fabFail := func(delay time.Duration) func() (io.Closer, error) {
		return func() (io.Closer, error) {
			time.Sleep(delay)
			return nil, errors.New("failed after sleep")
		}
	}

	ff1 := fabFail(time.Millisecond * 100)
	ff2 := fabFail(time.Millisecond * 200)
	ff3 := fabFail(time.Millisecond * 400)

	start := time.Now()
	res, err := resolveParallel(ff1, ff2, ff3)
	stop := time.Now()
	runDuration := stop.Sub(start)
	assert.Error(t, err)
	assert.Empty(t, res)
	assert.LessOrEqual(t, time.Millisecond*400, runDuration)
	assert.Less(t, runDuration, time.Millisecond*700)
}
