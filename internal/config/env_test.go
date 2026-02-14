package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type subConfig2 struct {
	StringVal string `mapstructure:"val"`
}
type testConfig struct {
	StringKey string `mapstructure:"string1"`
	IntKey    int    `mapstructure:"int2"`
	SubConfig struct {
		SubString string `mapstructure:"sub1"`
	}
	Sub             *subConfig2                        `mapstructure:"sub2"`
	unexportedField int                                `mapstructure:"shouldntexist"` //nolint:golint,unused
	MapVars         map[string]struct{ MapVal string } `mapstructure:"mapVars"`
}

func TestBindEnvToStruct(t *testing.T) {
	cfg := &testConfig{
		MapVars: map[string]struct{ MapVal string }{
			"mapKey": {"mapVal"},
		},
	}

	viperCfg := newViperIfMock(t)
	for _, bindName := range []string{"string1", "int2", "SubConfig.sub1", "sub2.val", "mapVars.mapKey.MapVal"} {
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

func TestDiscoverMapKeys(t *testing.T) {
	t.Setenv("SMOLMAILER_DKIM_SIGNER__RSA_SELECTOR", "foo")

	mapKeys := getPossibleMapKeys("dkim.signer", "SMOLMAILER")
	require.Len(t, mapKeys, 1)
	assert.Contains(t, mapKeys, "rsa")
}
