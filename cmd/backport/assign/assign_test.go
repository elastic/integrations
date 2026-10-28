// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package assign

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPick(t *testing.T) {
	yes := func(string) bool { return true }
	no := func(string) bool { return false }

	t.Run("author is not bot and has write access — use author", func(t *testing.T) {
		assert.Equal(t, "author", Pick(
			PRActor{Login: "author", IsBot: false},
			PRActor{Login: "merger", IsBot: false}, yes))
	})

	t.Run("author is bot — fall back to mergedBy", func(t *testing.T) {
		assert.Equal(t, "merger", Pick(
			PRActor{Login: "app/some-bot", IsBot: true},
			PRActor{Login: "merger", IsBot: false}, yes))
	})

	t.Run("author has no write access (external contributor) — fall back to mergedBy", func(t *testing.T) {
		onlyMerger := func(login string) bool { return login == "merger" }
		assert.Equal(t, "merger", Pick(
			PRActor{Login: "external-contributor", IsBot: false},
			PRActor{Login: "merger", IsBot: false}, onlyMerger))
	})

	t.Run("author is bot and mergedBy is bot — return empty string", func(t *testing.T) {
		assert.Equal(t, "", Pick(
			PRActor{Login: "app/bot-a", IsBot: true},
			PRActor{Login: "app/bot-b", IsBot: true}, yes))
	})

	t.Run("author is bot and mergedBy is empty — return empty string", func(t *testing.T) {
		assert.Equal(t, "", Pick(
			PRActor{Login: "app/bot", IsBot: true},
			PRActor{}, yes))
	})

	t.Run("author is bot and mergedBy lost write access — return empty string", func(t *testing.T) {
		assert.Equal(t, "", Pick(
			PRActor{Login: "app/bot", IsBot: true},
			PRActor{Login: "ex-maintainer", IsBot: false}, no))
	})
}
