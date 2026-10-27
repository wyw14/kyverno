package diff

import (
	"testing"

	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"github.com/stretchr/testify/assert"
)

func testKey(policy, rule, resource string) ruleKey {
	return ruleKey{
		policy:   policyKey{kind: "ClusterPolicy", name: policy},
		rule:     rule,
		resource: resourceKey{kind: "Pod", namespace: "default", name: resource},
	}
}

func result(status engineapi.RuleStatus) *ruleResult {
	return &ruleResult{status: status}
}

func TestCompareClassifications(t *testing.T) {
	oldResults := sideResults{
		testKey("p", "kept-pass", "r1"): result(engineapi.RuleStatusPass),
		testKey("p", "kept-fail", "r1"): result(engineapi.RuleStatusFail),
		testKey("p", "flip", "r1"):      result(engineapi.RuleStatusPass),
		testKey("p", "removed", "r1"):   result(engineapi.RuleStatusFail),
	}
	newResults := sideResults{
		testKey("p", "kept-pass", "r1"): result(engineapi.RuleStatusPass),
		testKey("p", "kept-fail", "r1"): result(engineapi.RuleStatusFail),
		testKey("p", "flip", "r1"):      result(engineapi.RuleStatusFail),
		testKey("p", "added", "r1"):     result(engineapi.RuleStatusFail),
	}
	report := compare(oldResults, newResults)
	byRule := map[string]Entry{}
	for _, entry := range report.Results {
		byRule[entry.Rule] = entry
	}
	assert.Equal(t, ChangeUnchanged, byRule["kept-pass"].Change)
	assert.Equal(t, "pass", *byRule["kept-pass"].OldResult)
	assert.Equal(t, "pass", *byRule["kept-pass"].NewResult)
	assert.Equal(t, ChangeUnchanged, byRule["kept-fail"].Change)
	assert.Equal(t, ChangeChanged, byRule["flip"].Change)
	assert.Equal(t, "pass", *byRule["flip"].OldResult)
	assert.Equal(t, "fail", *byRule["flip"].NewResult)
	// A rule missing on one side is absent (nil result), never reported as pass.
	assert.Equal(t, ChangeRemoved, byRule["removed"].Change)
	assert.Nil(t, byRule["removed"].NewResult)
	assert.Equal(t, "fail", *byRule["removed"].OldResult)
	assert.Equal(t, ChangeAdded, byRule["added"].Change)
	assert.Nil(t, byRule["added"].OldResult)
	assert.Equal(t, "fail", *byRule["added"].NewResult)
	assert.Equal(t, Summary{Added: 1, Removed: 1, Changed: 1, Unchanged: 2, NewFailures: 2}, report.Summary)
}

func TestCompareRuleRenameIsRemoveAndAdd(t *testing.T) {
	oldResults := sideResults{
		testKey("p", "old-name", "r1"): result(engineapi.RuleStatusPass),
	}
	newResults := sideResults{
		testKey("p", "new-name", "r1"): result(engineapi.RuleStatusPass),
	}
	report := compare(oldResults, newResults)
	assert.Len(t, report.Results, 2)
	// Rows are stably sorted on the rule name: "new-name" < "old-name".
	assert.Equal(t, ChangeAdded, report.Results[0].Change)
	assert.Equal(t, "new-name", report.Results[0].Rule)
	assert.Equal(t, ChangeRemoved, report.Results[1].Change)
	assert.Equal(t, "old-name", report.Results[1].Rule)
}

func TestIsNewFailure(t *testing.T) {
	cases := []struct {
		name string
		old  engineapi.RuleStatus
		new  engineapi.RuleStatus
		want bool
	}{
		{"absent to fail is new failure", "", engineapi.RuleStatusFail, true},
		{"pass to fail is new failure", engineapi.RuleStatusPass, engineapi.RuleStatusFail, true},
		{"skip to fail is new failure", engineapi.RuleStatusSkip, engineapi.RuleStatusFail, true},
		{"error to fail is new failure", engineapi.RuleStatusError, engineapi.RuleStatusFail, true},
		{"fail to fail is not new failure", engineapi.RuleStatusFail, engineapi.RuleStatusFail, false},
		{"fail to pass is not new failure", engineapi.RuleStatusFail, engineapi.RuleStatusPass, false},
		{"pass to error is not new failure", engineapi.RuleStatusPass, engineapi.RuleStatusError, false},
		{"pass to skip is not new failure", engineapi.RuleStatusPass, engineapi.RuleStatusSkip, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var old *ruleResult
			if tc.old != "" {
				old = result(tc.old)
			}
			assert.Equal(t, tc.want, isNewFailure(old, result(tc.new)))
		})
	}
}

func TestHasEvaluationErrors(t *testing.T) {
	assert.False(t, hasEvaluationErrors(
		sideResults{testKey("p", "a", "r"): result(engineapi.RuleStatusPass)},
		sideResults{testKey("p", "b", "r"): result(engineapi.RuleStatusFail)},
	))
	assert.True(t, hasEvaluationErrors(
		sideResults{testKey("p", "a", "r"): result(engineapi.RuleStatusPass)},
		sideResults{testKey("p", "b", "r"): result(engineapi.RuleStatusError)},
	))
}

func TestRecordKeepsWorstStatus(t *testing.T) {
	results := sideResults{}
	key := testKey("p", "rule", "r1")
	results.record(key, result(engineapi.RuleStatusPass))
	results.record(key, result(engineapi.RuleStatusSkip))
	assert.Equal(t, engineapi.RuleStatusSkip, results[key].status)
	results.record(key, result(engineapi.RuleStatusFail))
	assert.Equal(t, engineapi.RuleStatusFail, results[key].status)
	results.record(key, result(engineapi.RuleStatusError))
	assert.Equal(t, engineapi.RuleStatusError, results[key].status)
	results.record(key, result(engineapi.RuleStatusFail))
	assert.Equal(t, engineapi.RuleStatusError, results[key].status)
}

func TestSortEntriesIsStableAndComplete(t *testing.T) {
	oldResults := sideResults{
		{policy: policyKey{kind: "Policy", namespace: "team-a", name: "zebra"}, rule: "b", resource: resourceKey{kind: "Pod", namespace: "default", name: "z"}}: result(engineapi.RuleStatusPass),
		{policy: policyKey{kind: "ClusterPolicy"}, rule: "a", resource: resourceKey{group: "apps", kind: "Deployment", namespace: "default", name: "d"}}:        result(engineapi.RuleStatusPass),
		{policy: policyKey{kind: "Policy", namespace: "team-a", name: "alpha"}, rule: "a", resource: resourceKey{kind: "Pod", namespace: "default", name: "a"}}: result(engineapi.RuleStatusPass),
	}
	report := compare(oldResults, oldResults)
	assert.Len(t, report.Results, 3)
	// ClusterPolicy sorts before Policy.
	assert.Equal(t, "ClusterPolicy", report.Results[0].Policy.Kind)
	assert.Equal(t, "alpha", report.Results[1].Policy.Name)
	assert.Equal(t, "zebra", report.Results[2].Policy.Name)
	assert.Equal(t, "b", report.Results[2].Rule)
	assert.Equal(t, "z", report.Results[2].Resource.Name)
}
