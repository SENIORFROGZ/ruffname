// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseReplaceRules tests the compileReplaceRules helper function.
func TestParseRepaceRules(t *testing.T) {
	assert := assert.New(t)
	rules := []*ReplaceRule{
		{Name: "http.url", Pattern: "(token/)([^/]*)", Repl: "${1}?"},
		{Name: "http.url", Pattern: "guid", Repl: "[REDACTED]"},
		{Name: "custom.tag", Pattern: "(/foo/bar/).*", Repl: "${1}extra"},
	}
	err := compileReplaceRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		assert.Equal(r.Pattern, r.Re.String())
	}
}
