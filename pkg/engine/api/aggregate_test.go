package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCountRuleStatuses(t *testing.T) {
	t.Parallel()
	counts := CountRuleStatuses(
		*RulePass("r1", Validation, "ok", nil),
		*RuleFail("r2", Validation, "nope", nil),
		*RuleSkip("r3", Validation, "skipped", nil),
		*RuleError("r4", Validation, "boom", assert.AnError, nil),
		*RulePass("r5", Validation, "ok", nil),
		*RuleWarn("r6", Validation, "careful", nil),
	)
	assert.Equal(t, RuleStatusCounts{Pass: 2, Fail: 1, Warn: 1, Error: 1, Skip: 1}, counts)
	assert.Equal(t, 6, counts.Total())
}

func TestAggregateRuleResponses_CountsAndLatestReason(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_700_000_000, 0)
	responses := []RuleResponse{
		RuleFail("check-label", Validation, "missing label", nil).WithStats(NewExecutionStats(start, start.Add(time.Second))),
		RulePass("check-label", Validation, "label present", nil).WithStats(NewExecutionStats(start.Add(2*time.Second), start.Add(3*time.Second))),
		RuleSkip("other-rule", Validation, "not applicable", nil).WithStats(NewExecutionStats(start, start.Add(time.Second))),
	}
	outcomes := AggregateRuleResponses(responses...)
	assert.Len(t, outcomes, 2)
	// outcomes are sorted by rule name
	assert.Equal(t, "check-label", outcomes[0].Name)
	assert.Equal(t, 1, outcomes[0].Counts.Pass)
	assert.Equal(t, 1, outcomes[0].Counts.Fail)
	assert.Equal(t, RuleStatusPass, outcomes[0].Status)
	assert.Equal(t, "label present", outcomes[0].Reason)
	assert.Equal(t, start.Add(2*time.Second), outcomes[0].ObservedAt)
	assert.Equal(t, "other-rule", outcomes[1].Name)
	assert.Equal(t, 1, outcomes[1].Counts.Skip)
	assert.Equal(t, RuleStatusSkip, outcomes[1].Status)
}

// TestAggregateRuleResponses_ReplayIsIdempotent proves that an informer
// reconnect (or any path) replaying the exact same rule responses does not
// inflate the pass/fail/skip/error counts, and a newer observation wins.
func TestAggregateRuleResponses_ReplayIsIdempotent(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_700_000_000, 0)
	responses := []RuleResponse{
		RuleError("check-label", Validation, "variable unresolved", assert.AnError, nil).WithStats(NewExecutionStats(start, start.Add(time.Millisecond))),
		RuleSkip("precondition", Validation, "preconditions not met", nil).WithStats(NewExecutionStats(start, start.Add(time.Millisecond))),
	}
	first := AggregateRuleResponses(responses...)
	replayed := AggregateRuleResponses(append(responses, responses...)...)
	assert.Equal(t, first, replayed)
	for _, outcome := range replayed {
		assert.Equal(t, 1, outcome.Counts.Total(), "rule %s was double counted after replay", outcome.Name)
	}
}
