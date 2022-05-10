// Copyright 2020 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package redact contains a simple context signal for redacting requests.
package redact

import (
	"context"
)

type contextKey string

var redactKey = contextKey("redact")

// NewContext creates a new ctx with the reason for redaction.
func NewContext(ctx context.Context, reason string) context.Context {
	return context.WithValue(ctx, redactKey, reason)
}

// FromContext returns the redaction reason, if any.
func FromContext(ctx context.Context) (bool, string) {
	reason, ok := ctx.Value(redactKey).(string)
	return ok, reason
}
