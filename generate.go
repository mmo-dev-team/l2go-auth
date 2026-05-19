// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

// Package tools contains development tools and code generation directives.
//
// This file specifically manages the generation of Go code from SQL queries using sqlc.
//go:build tools

package tools

//go:generate sqlc generate -f sqlc.yaml
