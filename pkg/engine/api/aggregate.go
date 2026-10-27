package api

import (
	"slices"
	"time"
)

// RuleStatusCounts holds the number of rule observations per RuleStatus.
type RuleStatusCounts struct {
	// Pass is the number of passing observations.
	Pass int
	// Fail is the number of failing observations.
	Fail int
	// Warn is the number of warning observations (failed but not scored).
	Warn int
	// Error is the number of observations that could not be evaluated.
	Error int
	// Skip is the number of skipped observations.
	Skip int
}

// Total returns the number of de-duplicated observations counted across all
// statuses.
func (c RuleStatusCounts) Total() int {
	return c.Pass + c.Fail + c.Warn + c.Error + c.Skip
}

func (c *RuleStatusCounts) add(status RuleStatus) {
	switch status {
	case RuleStatusPass:
		c.Pass++
	case RuleStatusFail:
		c.Fail++
	case RuleStatusWarn:
		c.Warn++
	case RuleStatusError:
		c.Error++
	case RuleStatusSkip:
		c.Skip++
	}
}

// RuleOutcome is the aggregated view of a single rule on a single resource:
// how many pass/fail/warn/error/skip observations were seen and the most
// recent status and reason.
type RuleOutcome struct {
	// Name is the rule name.
	Name string
	// Counts contains the de-duplicated observations per status.
	Counts RuleStatusCounts
	// Status is the most recently observed rule status.
	Status RuleStatus
	// Reason is the message of the most recently observed rule response.
	Reason string
	// ObservedAt is the stats timestamp of the most recently observed response.
	ObservedAt time.Time
}

// CountRuleStatuses tallies rule responses by status. Every supplied response
// is counted once; use AggregateRuleResponses when the same evaluation may be
// replayed and re-counting must be avoided.
func CountRuleStatuses(responses ...RuleResponse) RuleStatusCounts {
	var counts RuleStatusCounts
	for i := range responses {
		counts.add(responses[i].Status())
	}
	return counts
}

// AggregateRuleResponses folds rule responses into one RuleOutcome per rule
// name.
//
// Observations are de-duplicated by (status, reason, stats timestamp): feeding
// the same responses twice (for example when an informer reconnect replays an
// evaluation or a response is delivered through both the admission and the
// background path) never increments the counts twice. When several distinct
// observations exist for a rule, the most recent one wins (by ExecutionStats
// time, with later slice positions winning ties) and determines Status,
// Reason and ObservedAt. Outcomes are returned sorted by rule name so callers
// get a stable order for pagination.
func AggregateRuleResponses(responses ...RuleResponse) []RuleOutcome {
	type identity struct {
		status RuleStatus
		reason string
		unixNs int64
	}
	type accumulator struct {
		outcome RuleOutcome
		seen    map[identity]struct{}
	}
	indexes := map[string]*accumulator{}
	for i := range responses {
		response := &responses[i]
		acc, ok := indexes[response.Name()]
		if !ok {
			acc = &accumulator{
				outcome: RuleOutcome{Name: response.Name()},
				seen:    map[identity]struct{}{},
			}
			indexes[response.Name()] = acc
		}
		observedAt := response.Stats().Time()
		key := identity{status: response.Status(), reason: response.Message(), unixNs: observedAt.UnixNano()}
		if _, exists := acc.seen[key]; !exists {
			acc.seen[key] = struct{}{}
			acc.outcome.Counts.add(response.Status())
		}
		// Zero timestamps are comparable: the first response wins only when
		// it is strictly more recent, otherwise the later slice position wins.
		if acc.outcome.Status == "" || !observedAt.Before(acc.outcome.ObservedAt) {
			acc.outcome.Status = response.Status()
			acc.outcome.Reason = response.Message()
			acc.outcome.ObservedAt = observedAt
		}
	}
	outcomes := make([]RuleOutcome, 0, len(indexes))
	for _, acc := range indexes {
		outcomes = append(outcomes, acc.outcome)
	}
	slices.SortFunc(outcomes, func(a, b RuleOutcome) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return outcomes
}
