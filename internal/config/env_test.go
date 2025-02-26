package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	StringKey string `mapstructure:"string1"`
	IntKey    int    `mapstructure:"int2"`
	SubConfig struct {
		SubString string `mapstructure:"sub1"`
	}
	unexportedField int `mapstructure:"shouldntexist"` //nolint:golint,unused
}

func TestBindEnvToStruct(t *testing.T) {
	cfg := &testConfig{}

	viperCfg := new(viperIfMock)
	for _, bindName := range []string{"string1", "int2", "SubConfig.sub1"} {
		viperCfg.On("BindEnv", bindName).Once().Return(nil)
	}

	err := BindStructToEnv(cfg, viperCfg)
	require.NoError(t, err)

	viperCfg.AssertExpectations(t)
}

func TestConcatenateConfigKeys(t *testing.T) {
	for _, testCfg := range []struct {
		keys         []string
		expectedPath string
	}{
		{
			keys:         []string{"", "foo"},
			expectedPath: "foo",
		},
		{
			keys:         []string{"foo", "bar"},
			expectedPath: "foo.bar",
		},
		{
			keys:         []string{"foo.bar", "baz"},
			expectedPath: "foo.bar.baz",
		},
	} {
		configPath := concatenateConfigKeys(testCfg.keys...)
		assert.Equal(t, testCfg.expectedPath, configPath)
	}
}
