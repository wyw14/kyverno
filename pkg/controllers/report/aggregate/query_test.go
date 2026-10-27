package aggregate_test

import (
	"testing"
	"time"

	reportsv1 "github.com/kyverno/kyverno/api/reports/v1"
	"github.com/kyverno/kyverno/pkg/controllers/report/aggregate"
	"github.com/kyverno/kyverno/pkg/openreports"
	reportutils "github.com/kyverno/kyverno/pkg/utils/report"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

type reportFixture struct {
	name      string
	cluster   bool
	namespace string
	resource  string
	uid       string
	kind      string
	deleted   bool
	labels    map[string]string
	ownerUID  string
	results   []openreportsv1alpha1.ReportResult
}

func buildReport(f reportFixture) reportsv1.ReportInterface {
	labels := map[string]string{}
	if f.uid != "" {
		labels[reportutils.LabelResourceUid] = f.uid
	}
	if f.kind != "" {
		labels[reportutils.LabelResourceKind] = f.kind
	}
	for key, value := range f.labels {
		labels[key] = value
	}
	annotations := map[string]string{
		reportutils.AnnotationResourceNamespace: f.namespace,
		reportutils.AnnotationResourceName:      f.resource,
	}
	meta := metav1.ObjectMeta{
		Name:        f.name,
		Namespace:   f.namespace,
		Labels:      labels,
		Annotations: annotations,
	}
	if f.ownerUID != "" {
		meta.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "v1",
			Kind:       f.kind,
			Name:       f.resource,
			UID:        types.UID(f.ownerUID),
		}}
	}
	if f.deleted {
		meta.DeletionTimestamp = &metav1.Time{Time: time.Unix(50, 0)}
	}
	spec := reportsv1.EphemeralReportSpec{Results: f.results}
	if f.cluster {
		return &reportsv1.ClusterEphemeralReport{ObjectMeta: meta, Spec: spec}
	}
	return &reportsv1.EphemeralReport{ObjectMeta: meta, Spec: spec}
}

func kyvernoResult(policy, rule string, status openreportsv1alpha1.Result, reason string, ts int64) openreportsv1alpha1.ReportResult {
	return openreportsv1alpha1.ReportResult{
		Source:      reportutils.SourceKyverno,
		Policy:      policy,
		Rule:        rule,
		Result:      status,
		Description: reason,
		Timestamp:   metav1.Timestamp{Seconds: ts},
	}
}

func legacyMaps(policies map[string][]string) aggregate.Maps {
	pol := map[string]aggregate.PolicyMapEntry{}
	for policy, rules := range policies {
		pol[policy] = aggregate.PolicyMapEntry{Rules: sets.New(rules...)}
	}
	return aggregate.Maps{Pol: pol}
}

// TestQueryRuleAndResourceAggregations_ClusterScopedPolicy proves a cluster
// policy result against a cluster-scoped resource aggregates into an
// empty-namespace row carrying the policy revision and pass/fail counts.
func TestQueryRuleAndResourceAggregations_ClusterScopedPolicy(t *testing.T) {
	t.Parallel()
	maps := legacyMaps(map[string][]string{
		"deny-privileged": {"check-priv", "check-run-as-root"},
	})
	report := buildReport(reportFixture{
		name:     "cephr-node-1",
		cluster:  true,
		resource: "node-1",
		uid:      "uid-node-1",
		kind:     "Node",
		labels:   map[string]string{reportutils.LabelPrefixClusterPolicy + "deny-privileged": "3"},
		results: []openreportsv1alpha1.ReportResult{
			kyvernoResult("deny-privileged", "check-priv", openreports.StatusFail, "privileged containers are blocked", 100),
			kyvernoResult("deny-privileged", "check-run-as-root", openreports.StatusPass, "runs as non-root", 110),
			// a rule of a policy that is no longer active must be filtered out
			kyvernoResult("removed-policy", "ghost-rule", openreports.StatusFail, "stale", 90),
		},
	})
	byRule, byResource := aggregate.QueryRuleAndResourceAggregations(maps, report)
	require.Len(t, byRule, 2)
	for _, row := range byRule {
		assert.Equal(t, "", row.Namespace, "cluster-scoped resources must aggregate in the empty namespace")
		assert.Equal(t, "3", row.PolicyRevision)
	}
	priv := findRuleRow(t, byRule, "", "deny-privileged", "check-priv", "3")
	assert.Equal(t, openreports.StatusFail, string(priv.LastResult))
	assert.Equal(t, "privileged containers are blocked", priv.LastReason)
	assert.Equal(t, reportutils.StatusCounts{Fail: 1}, priv.Counts)
	root := findRuleRow(t, byRule, "", "deny-privileged", "check-run-as-root", "3")
	assert.Equal(t, reportutils.StatusCounts{Pass: 1}, root.Counts)

	require.Len(t, byResource, 1)
	assert.Equal(t, "", byResource[0].Namespace)
	assert.Equal(t, "uid-node-1", string(byResource[0].ResourceUID))
	assert.Equal(t, reportutils.StatusCounts{Pass: 1, Fail: 1}, byResource[0].Counts)
}

// TestQueryRuleAndResourceAggregations_DeletedResource covers the deleted
// resource paths: tombstoned reports are ignored and reports left behind for
// a deleted/no-longer-active policy produce no aggregated rows, while live
// active resources keep aggregating.
func TestQueryRuleAndResourceAggregations_DeletedResource(t *testing.T) {
	t.Parallel()
	maps := legacyMaps(map[string][]string{
		"team-a/require-label": {"check-label"},
	})
	tombstone := buildReport(reportFixture{
		name:      "ephr-gone",
		namespace: "team-a",
		resource:  "pod-gone",
		uid:       "uid-gone",
		kind:      "Pod",
		deleted:   true,
		labels:    map[string]string{reportutils.LabelPrefixPolicy + "require-label": "10"},
		results: []openreportsv1alpha1.ReportResult{
			kyvernoResult("team-a/require-label", "check-label", openreports.StatusFail, "missing app label", 100),
		},
	})
	stalePolicy := buildReport(reportFixture{
		name:      "ephr-stale",
		namespace: "team-a",
		resource:  "pod-stale",
		uid:       "uid-stale",
		kind:      "Pod",
		labels:    map[string]string{reportutils.LabelPrefixPolicy + "removed-policy": "1"},
		results: []openreportsv1alpha1.ReportResult{
			kyvernoResult("team-a/removed-policy", "ghost-rule", openreports.StatusFail, "policy deleted", 100),
		},
	})
	live := buildReport(reportFixture{
		name:      "ephr-live",
		namespace: "team-a",
		resource:  "pod-live",
		uid:       "uid-live",
		kind:      "Pod",
		labels:    map[string]string{reportutils.LabelPrefixPolicy + "require-label": "10"},
		results: []openreportsv1alpha1.ReportResult{
			kyvernoResult("team-a/require-label", "check-label", openreports.StatusPass, "labels ok", 200),
		},
	})
	byRule, byResource := aggregate.QueryRuleAndResourceAggregations(maps, tombstone, stalePolicy, live)
	require.Len(t, byRule, 1)
	assert.Equal(t, "team-a", byRule[0].Namespace)
	assert.Equal(t, reportutils.StatusCounts{Pass: 1}, byRule[0].Counts)
	require.Len(t, byResource, 1)
	assert.Equal(t, "uid-live", string(byResource[0].ResourceUID))

	// once the live report disappears too (resource deleted), nothing remains
	emptyRules, emptyResources := aggregate.QueryRuleAndResourceAggregations(maps, tombstone, stalePolicy)
	assert.Empty(t, emptyRules)
	assert.Empty(t, emptyResources)
}

// TestQueryRuleAndResourceAggregations_InformerReconnect simulates a reconnect
// re-listing overlapping reports for the same resource: one report resolves
// the resource UID from its owner reference (permanent report shape), the
// other from the audit resource.uid label (ephemeral report shape). The
// MergeReports dedup must count the (policy, rule, resource) fact once and
// keep the most recent observation.
func TestQueryRuleAndResourceAggregations_InformerReconnect(t *testing.T) {
	t.Parallel()
	maps := legacyMaps(map[string][]string{
		"deny-privileged": {"check-priv"},
	})
	permanentLike := buildReport(reportFixture{
		name:     "uid-node-1",
		cluster:  true,
		resource: "node-1",
		ownerUID: "uid-node-1",
		kind:     "Node",
		labels:   map[string]string{reportutils.LabelPrefixClusterPolicy + "deny-privileged": "3"},
		results: []openreportsv1alpha1.ReportResult{
			kyvernoResult("deny-privileged", "check-priv", openreports.StatusFail, "privileged containers are blocked", 100),
		},
	})
	ephemeral := buildReport(reportFixture{
		name:     "cephr-node-1",
		cluster:  true,
		resource: "node-1",
		uid:      "uid-node-1",
		kind:     "Node",
		labels:   map[string]string{reportutils.LabelPrefixClusterPolicy + "deny-privileged": "3"},
		results: []openreportsv1alpha1.ReportResult{
			kyvernoResult("deny-privileged", "check-priv", openreports.StatusPass, "configuration fixed", 200),
		},
	})
	inputs := []reportsv1.ReportInterface{permanentLike, ephemeral}
	first, firstResources := aggregate.QueryRuleAndResourceAggregations(maps, inputs...)
	// a reconnect re-lists the very same objects; append them once more
	replayed, replayedResources := aggregate.QueryRuleAndResourceAggregations(maps, append(inputs, inputs...)...)
	require.Len(t, first, 1)
	require.Len(t, replayed, 1)
	assert.Equal(t, first[0].Counts, replayed[0].Counts)
	assert.Equal(t, reportutils.StatusCounts{Pass: 1}, replayed[0].Counts)
	assert.Equal(t, openreportsv1alpha1.Result(openreports.StatusPass), replayed[0].LastResult)
	assert.Equal(t, "configuration fixed", replayed[0].LastReason)
	require.Len(t, firstResources, 1)
	require.Len(t, replayedResources, 1)
	assert.Equal(t, firstResources[0].Counts, replayedResources[0].Counts)
	assert.Equal(t, reportutils.StatusCounts{Pass: 1}, replayedResources[0].Counts)
}

func findRuleRow(t *testing.T, rows []reportutils.RuleAggregationRow, namespace, policy, rule, revision string) reportutils.RuleAggregationRow {
	t.Helper()
	for _, row := range rows {
		if row.Namespace == namespace && row.Policy == policy && row.Rule == rule && row.PolicyRevision == revision {
			return row
		}
	}
	require.Failf(t, "rule aggregation row not found", "namespace=%q policy=%q rule=%q revision=%q", namespace, policy, rule, revision)
	return reportutils.RuleAggregationRow{}
}
