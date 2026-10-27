package diff

import (
	"sort"

	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
)

// policyKey identifies a Policy or ClusterPolicy.
type policyKey struct {
	kind      string
	namespace string
	name      string
}

// resourceKey identifies a resource by group/kind/namespace/name, the alignment
// granularity required for comparing results.
type resourceKey struct {
	group     string
	kind      string
	namespace string
	name      string
}

// ruleKey is the full alignment key: policy identity + rule name + resource identity.
type ruleKey struct {
	policy   policyKey
	rule     string
	resource resourceKey
}

// ruleResult is the outcome of one validate rule on one resource.
type ruleResult struct {
	status  engineapi.RuleStatus
	message string
}

// sideResults holds every rule/resource result computed for one policy set.
type sideResults map[ruleKey]*ruleResult

// ChangeType describes how a cell differs between the two policy sets.
type ChangeType string

const (
	// ChangeAdded means the rule exists only in the new policy set.
	ChangeAdded ChangeType = "added"
	// ChangeRemoved means the rule exists only in the old policy set.
	ChangeRemoved ChangeType = "removed"
	// ChangeChanged means the rule exists on both sides but its result differs.
	ChangeChanged ChangeType = "changed"
	// ChangeUnchanged means the rule exists on both sides with the same result.
	ChangeUnchanged ChangeType = "unchanged"
)

// PolicyRef references a Policy or ClusterPolicy.
type PolicyRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// ResourceRef references the resource a rule was evaluated against.
type ResourceRef struct {
	APIGroup  string `json:"apiGroup,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Entry is one aligned rule result. A nil OldResult or NewResult means the rule
// did not exist on that side; it is rendered as "none", never as "pass".
type Entry struct {
	Policy    PolicyRef   `json:"policy"`
	Rule      string      `json:"rule"`
	Resource  ResourceRef `json:"resource"`
	OldResult *string     `json:"oldResult"`
	NewResult *string     `json:"newResult"`
	Change    ChangeType  `json:"change"`
	// Message is the engine message of the most severe side, useful to explain failures.
	Message string `json:"message,omitempty"`
}

// Summary aggregates the comparison.
type Summary struct {
	Added       int `json:"added"`
	Removed     int `json:"removed"`
	Changed     int `json:"changed"`
	Unchanged   int `json:"unchanged"`
	NewFailures int `json:"newFailures"`
}

// Report is the full comparison result.
type Report struct {
	Summary Summary `json:"summary"`
	Results []Entry `json:"results"`
}

// statusRank orders duplicate results a rule may produce so the worst one wins.
func statusRank(status engineapi.RuleStatus) int {
	switch status {
	case engineapi.RuleStatusError:
		return 5
	case engineapi.RuleStatusFail:
		return 4
	case engineapi.RuleStatusWarn:
		return 3
	case engineapi.RuleStatusSkip:
		return 2
	case engineapi.RuleStatusPass:
		return 1
	default:
		return 0
	}
}

// record stores the result for a key, keeping the most severe result on duplicates.
func (s sideResults) record(key ruleKey, result *ruleResult) {
	if existing, ok := s[key]; ok {
		if statusRank(result.status) <= statusRank(existing.status) {
			return
		}
	}
	s[key] = result
}

// isNewFailure reports whether the cell represents a failure that did not
// exist before: the new side fails while the old side did not (including a
// newly added rule or a pass/skip/error -> fail transition).
func isNewFailure(old, new *ruleResult) bool {
	if new == nil || new.status != engineapi.RuleStatusFail {
		return false
	}
	return old == nil || old.status != engineapi.RuleStatusFail
}

// compare aligns the two sides by key, classifies every cell and returns a
// stably sorted report. The result set is fully deterministic: keys are sorted
// lexicographically on every alignment component.
func compare(oldResults, newResults sideResults) *Report {
	keys := make(map[ruleKey]struct{}, len(oldResults)+len(newResults))
	for key := range oldResults {
		keys[key] = struct{}{}
	}
	for key := range newResults {
		keys[key] = struct{}{}
	}
	report := &Report{Results: make([]Entry, 0, len(keys))}
	for key := range keys {
		old := oldResults[key]
		new := newResults[key]
		entry := Entry{
			Policy: PolicyRef{
				Kind:      key.policy.kind,
				Namespace: key.policy.namespace,
				Name:      key.policy.name,
			},
			Rule: key.rule,
			Resource: ResourceRef{
				APIGroup:  key.resource.group,
				Kind:      key.resource.kind,
				Namespace: key.resource.namespace,
				Name:      key.resource.name,
			},
		}
		if old != nil {
			result := string(old.status)
			entry.OldResult = &result
			entry.Message = old.message
		}
		if new != nil {
			result := string(new.status)
			entry.NewResult = &result
			// Prefer the new side's message when the cell is not a pure removal.
			if new.message != "" {
				entry.Message = new.message
			}
		}
		switch {
		case old == nil && new != nil:
			entry.Change = ChangeAdded
			report.Summary.Added++
		case old != nil && new == nil:
			entry.Change = ChangeRemoved
			report.Summary.Removed++
		case old != nil && new != nil && old.status != new.status:
			entry.Change = ChangeChanged
			report.Summary.Changed++
		default:
			entry.Change = ChangeUnchanged
			report.Summary.Unchanged++
		}
		if isNewFailure(old, new) {
			report.Summary.NewFailures++
		}
		report.Results = append(report.Results, entry)
	}
	sortEntries(report.Results)
	return report
}

// sortEntries sorts stably on the complete alignment key.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Policy.Kind != b.Policy.Kind {
			return a.Policy.Kind < b.Policy.Kind
		}
		if a.Policy.Namespace != b.Policy.Namespace {
			return a.Policy.Namespace < b.Policy.Namespace
		}
		if a.Policy.Name != b.Policy.Name {
			return a.Policy.Name < b.Policy.Name
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if ra, rb := a.Resource.APIGroup, b.Resource.APIGroup; ra != rb {
			return ra < rb
		}
		if a.Resource.Kind != b.Resource.Kind {
			return a.Resource.Kind < b.Resource.Kind
		}
		if a.Resource.Namespace != b.Resource.Namespace {
			return a.Resource.Namespace < b.Resource.Namespace
		}
		return a.Resource.Name < b.Resource.Name
	})
}

// hasEvaluationErrors reports whether any rule on either side ended in error.
func hasEvaluationErrors(results ...sideResults) bool {
	for _, side := range results {
		for _, result := range side {
			if result.status == engineapi.RuleStatusError {
				return true
			}
		}
	}
	return false
}
