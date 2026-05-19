// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"testing"
)

func TestCleanBytesToString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"Normal string", []byte("hello"), "hello"},
		{"Null terminated", []byte("hello\x00\x00"), "hello"},
		{"Space padded", []byte("hello  "), "hello"},
		{"Leading padding", []byte("\x00\x00hello\x00"), "hello"},
		{"Leading and trailing spaces", []byte("  hello  "), "hello"},
		{"All nulls", []byte("\x00\x00\x00"), ""},
		{"Empty slice", []byte(""), ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := cleanBytesToString(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, actual)
			}
		})
	}
}
