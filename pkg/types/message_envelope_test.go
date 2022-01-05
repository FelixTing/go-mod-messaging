//
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package types

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMessageEnvelope(t *testing.T) {

	expectedCorrelationId := "this is my correlation id"
	expectedContentType := "application/json"
	expectedPayload := `{"data" : "myData"}`

	// lint:ignore SA1029 legacy
	// nolint:staticcheck // See golangci-lint #741
	ctx := context.WithValue(context.Background(), correlationId, expectedCorrelationId)
	// lint:ignore SA1029 legacy
	// nolint:staticcheck // See golangci-lint #741
	ctx = context.WithValue(ctx, contentType, expectedContentType)

	envelope := NewMessageEnvelope([]byte(expectedPayload), ctx)

	assert.Equal(t, expectedCorrelationId, envelope.CorrelationID)
	assert.Equal(t, expectedContentType, envelope.ContentType)
	assert.Equal(t, expectedPayload, string(envelope.Payload))
}

func TestNewMessageEnvelopeEmpty(t *testing.T) {

	envelope := NewMessageEnvelope([]byte{}, context.Background())

	assert.Empty(t, envelope.CorrelationID)
	assert.Empty(t, envelope.ContentType)
	assert.Empty(t, envelope.Payload)
}
