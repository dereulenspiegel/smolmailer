package smolmailer

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockCloser struct {
	mock.Mock
}

func (m *mockCloser) Close() error {
	return m.Called().Error(0)
}

func fabFail(delay time.Duration) func() (io.Closer, error) {
	return func() (io.Closer, error) {
		time.Sleep(delay)
		return nil, errors.New("failed after sleep")
	}
}

func TestResolveParallelSuccess(t *testing.T) {
	unusedResult := new(mockCloser)
	unusedResult.On("Close").Once().Return(nil)

	fSlow := func() (io.Closer, error) {
		time.Sleep(time.Millisecond * 310)

		return unusedResult, nil
	}

	usedResult := new(mockCloser)

	fSuccess := func() (io.Closer, error) {
		time.Sleep(time.Millisecond * 300)
		return usedResult, nil
	}

	ff1 := fabFail(time.Millisecond * 100)
	ff2 := fabFail(time.Millisecond * 200)
	ff3 := fabFail(time.Millisecond * 400)

	start := time.Now()
	res, err := resolveParallel(ff1, fSlow, fSuccess, ff2, ff3)
	stop := time.Now()
	runDuration := stop.Sub(start)
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.LessOrEqual(t, time.Millisecond*300, runDuration)
	assert.Less(t, runDuration, time.Millisecond*400)

	time.Sleep(time.Millisecond * 400)
	unusedResult.AssertExpectations(t)
	usedResult.AssertNotCalled(t, "Close")
}

func TestResolveParallelFail(t *testing.T) {
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
