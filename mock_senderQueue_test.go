// Code generated by mockery v2.50.4. DO NOT EDIT.

package smolmailer

import mock "github.com/stretchr/testify/mock"

// senderQueueMock is an autogenerated mock type for the senderQueue type
type senderQueueMock struct {
	mock.Mock
}

type senderQueueMock_Expecter struct {
	mock *mock.Mock
}

func (_m *senderQueueMock) EXPECT() *senderQueueMock_Expecter {
	return &senderQueueMock_Expecter{mock: &_m.Mock}
}

// Receive provides a mock function with no fields
func (_m *senderQueueMock) Receive() (*QueuedMessage, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Receive")
	}

	var r0 *QueuedMessage
	var r1 error
	if rf, ok := ret.Get(0).(func() (*QueuedMessage, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *QueuedMessage); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*QueuedMessage)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// senderQueueMock_Receive_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Receive'
type senderQueueMock_Receive_Call struct {
	*mock.Call
}

// Receive is a helper method to define mock.On call
func (_e *senderQueueMock_Expecter) Receive() *senderQueueMock_Receive_Call {
	return &senderQueueMock_Receive_Call{Call: _e.mock.On("Receive")}
}

func (_c *senderQueueMock_Receive_Call) Run(run func()) *senderQueueMock_Receive_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *senderQueueMock_Receive_Call) Return(_a0 *QueuedMessage, _a1 error) *senderQueueMock_Receive_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *senderQueueMock_Receive_Call) RunAndReturn(run func() (*QueuedMessage, error)) *senderQueueMock_Receive_Call {
	_c.Call.Return(run)
	return _c
}

// newSenderQueueMock creates a new instance of senderQueueMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newSenderQueueMock(t interface {
	mock.TestingT
	Cleanup(func())
}) *senderQueueMock {
	mock := &senderQueueMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}