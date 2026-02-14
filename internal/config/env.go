package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
)

type viperIf interface {
	BindEnv(input ...string) error
	GetEnvPrefix() string
}

func BindStructToEnv(configStruct any, viperConf viperIf) error {
	return bindStructFieldsToEnv("", configStruct, viperConf)
}

func bindStructFieldsToEnv(baseName string, configStruct any, viperConf viperIf) error {
	x := reflect.TypeOf(configStruct)
	y := reflect.ValueOf(configStruct)
	if x.Kind() == reflect.Pointer {
		x = x.Elem()
		y = y.Elem()
	}

	for i := 0; i < x.NumField(); i++ {
		field := x.Field(i)
		if !field.IsExported() {
			continue
		}
		configPath := getConfigPathForField(baseName, field)
		switch field.Type.Kind() { //nolint:golint,exhaustive
		case reflect.Struct:
			fieldValue := y.FieldByName(field.Name)
			if err := bindStructFieldsToEnv(configPath, fieldValue.Interface(), viperConf); err != nil {
				return err
			}
		case reflect.Pointer:
			zeroVal := reflect.New(field.Type)
			fieldKind := reflect.TypeOf(zeroVal.Elem()).Kind()

			switch fieldKind { //nolint:golint,exhaustive
			case reflect.Struct:
				if err := bindStructFieldsToEnv(configPath, zeroVal.Elem().Interface(), viperConf); err != nil {
					return err
				}
			default:
				if err := bindFieldToEnv(configPath, viperConf); err != nil {
					return err
				}
			}
		case reflect.Map:
			mapValType := field.Type.Elem()
			mapKeys := getPossibleMapKeys(configPath, viperConf.GetEnvPrefix())

			for _, key := range mapKeys {
				val := reflect.New(mapValType)
				bindStructFieldsToEnv(concatenateConfigKeys(configPath, key), val.Elem().Interface(), viperConf)
			}
		default:
			if err := bindFieldToEnv(configPath, viperConf); err != nil {
				return err
			}
		}
	}
	return nil
}

func getPossibleMapKeys(configPath string, envPrefix string) []string {
	envVars := os.Environ()
	configEnv := strings.ToUpper(strings.ReplaceAll(envPrefix+"_"+configPath, ".", "_"))

	mapKeys := make([]string, 0, 10)

	for _, envVar := range envVars {
		if strings.HasPrefix(envVar, configEnv) {
			baseEnv := strings.Replace(envVar, configEnv, "", 1)
			baseEnv = strings.TrimLeft(baseEnv, "_")
			configPaths := strings.Split(baseEnv, "_")
			if len(configPaths) > 0 {
				mapKeys = append(mapKeys, strings.ToLower(configPaths[0]))
			}
		}
	}
	return mapKeys
}

func bindFieldToEnv(configPath string, viperConf viperIf) error {
	if err := viperConf.BindEnv(configPath); err != nil {
		return fmt.Errorf("failed to bind config (%s) to env: %w", configPath, err)
	}
	return nil
}

func getConfigPathForField(baseName string, field reflect.StructField) string {
	name := field.Name
	tagName := parseStructTagName(field.Tag.Get("mapstructure"))
	if tagName != "" {
		name = tagName
	}
	return concatenateConfigKeys(baseName, name)
}

const tagValueSeparator = ","
const configKeySeparator = "."

func concatenateConfigKeys(configKeys ...string) string {
	nonEmptyKeys := make([]string, 0, len(configKeys))
	for _, configKey := range configKeys {
		if configKey != "" {
			nonEmptyKeys = append(nonEmptyKeys, configKey)
		}
	}
	return strings.Join(nonEmptyKeys, configKeySeparator)
}

func parseStructTagName(tag string) string {
	if strings.Contains(tag, tagValueSeparator) {
		parts := strings.Split(tag, tagValueSeparator)
		if len(parts) > 0 {
			return parts[0]
		}
		return tag
	}
	return tag
}
