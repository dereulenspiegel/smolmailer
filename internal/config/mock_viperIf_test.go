// Code generated by mockery v2.51.1. DO NOT EDIT.

package config

import mock "github.com/stretchr/testify/mock"

// viperIfMock is an autogenerated mock type for the viperIf type
type viperIfMock struct {
	mock.Mock
}

type viperIfMock_Expecter struct {
	mock *mock.Mock
}

func (_m *viperIfMock) EXPECT() *viperIfMock_Expecter {
	return &viperIfMock_Expecter{mock: &_m.Mock}
}

// BindEnv provides a mock function with given fields: input
func (_m *viperIfMock) BindEnv(input ...string) error {
	_va := make([]interface{}, len(input))
	for _i := range input {
		_va[_i] = input[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for BindEnv")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(...string) error); ok {
		r0 = rf(input...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// viperIfMock_BindEnv_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BindEnv'
type viperIfMock_BindEnv_Call struct {
	*mock.Call
}

// BindEnv is a helper method to define mock.On call
//   - input ...string
func (_e *viperIfMock_Expecter) BindEnv(input ...interface{}) *viperIfMock_BindEnv_Call {
	return &viperIfMock_BindEnv_Call{Call: _e.mock.On("BindEnv",
		append([]interface{}{}, input...)...)}
}

func (_c *viperIfMock_BindEnv_Call) Run(run func(input ...string)) *viperIfMock_BindEnv_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]string, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(string)
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *viperIfMock_BindEnv_Call) Return(_a0 error) *viperIfMock_BindEnv_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *viperIfMock_BindEnv_Call) RunAndReturn(run func(...string) error) *viperIfMock_BindEnv_Call {
	_c.Call.Return(run)
	return _c
}

// newViperIfMock creates a new instance of viperIfMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newViperIfMock(t interface {
	mock.TestingT
	Cleanup(func())
}) *viperIfMock {
	mock := &viperIfMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
