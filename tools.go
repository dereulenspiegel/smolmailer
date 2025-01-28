//go:build tools
// +build tools

package smolmailer

import (
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/vektra/mockery/v2"
)
