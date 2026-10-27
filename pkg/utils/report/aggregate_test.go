package report

import (
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	reportsv1 "github.com/kyverno/kyverno/api/reports/v1"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"github.com/kyverno/kyverno/pkg/openreports"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ruleResult(source, policy, rule string, status openreportsv1alpha1.Result, reason string, ts int64) openreportsv1alpha1.ReportResult {
	return openreportsv1alpha1.ReportResult{
		Source:      source,
		Policy:      policy,
		Rule:        rule,
		Result:      status,
		Description: reason,
		Timestamp:   metav1.Timestamp{Seconds: ts},
	}
}

// buildEphemeralReport creates an ephemeral report (namespaced or cluster
// scoped) carrying the standard audit labels/annotations and policy revision
// labels.
func buildEphemeralReport(t *testing.T, cluster bool, name, namespace, resourceName, uid, kind string, deleted bool, revisionLabels map[string]string, results ...openreportsv1alpha1.ReportResult) reportsv1.ReportInterface {
	t.Helper()
	labels := map[string]string{
		LabelResourceUid:  uid,
		LabelResourceKind: kind,
	}
	for key, value := range revisionLabels {
		labels[key] = value
	}
	annotations := map[string]string{
		AnnotationResourceNamespace: namespace,
		AnnotationResourceName:      resourceName,
	}
	meta := metav1.ObjectMeta{
		Name:        name,
		Labels:      labels,
		Annotations: annotations,
	}
	if deleted {
		meta.DeletionTimestamp = &metav1.Time{Time: time.Unix(50, 0)}
	}
	if cluster {
		return &reportsv1.ClusterEphemeralReport{ObjectMeta: meta, Spec: reportsv1.EphemeralReportSpec{Results: results}}
	}
	meta.Namespace = namespace
	return &reportsv1.EphemeralReport{ObjectMeta: meta, Spec: reportsv1.EphemeralReportSpec{Results: results}}
}

func findRuleRow(t *testing.T, rows []RuleAggregationRow, namespace, policy, rule, revision string) RuleAggregationRow {
	t.Helper()
	for _, row := range rows {
		if row.Namespace == namespace && row.Policy == policy && row.Rule == rule && row.PolicyRevision == revision {
			return row
		}
	}
	require.Failf(t, "rule aggregation row not found", "namespace=%q policy=%q rule=%q revision=%q", namespace, policy, rule, revision)
	return RuleAggregationRow{}
}

func findResourceRow(t *testing.T, rows []ResourceAggregationRow, namespace, uid string) ResourceAggregationRow {
	t.Helper()
	for _, row := range rows {
		if row.Namespace == namespace && string(row.ResourceUID) == uid {
			return row
		}
	}
	require.Failf(t, "resource aggregation row not found", "namespace=%q uid=%q", namespace, uid)
	return ResourceAggregationRow{}
}

func TestAggregateByRuleAndResource_NamespacedAndClusterScoped(t *testing.T) {
	t.Parallel()
	pod1 := buildEphemeralReport(t, false, "ephr-pod1", "team-a", "pod-1", "uid-1", "Pod", false,
		map[string]string{LabelPrefixPolicy + "require-label": "10"},
		ruleResult(SourceKyverno, "team-a/require-label", "check-label", openreports.StatusFail, "missing app label", 100),
	)
	pod2 := buildEphemeralReport(t, false, "ephr-pod2", "team-a", "pod-2", "uid-2", "Pod", false,
		map[string]string{LabelPrefixPolicy + "require-label": "10"},
		ruleResult(SourceKyverno, "team-a/require-label", "check-label", openreports.StatusPass, "labels ok", 200),
	)
	node := buildEphemeralReport(t, true, "cephr-node1", "", "node-1", "uid-3", "Node", false,
		map[string]string{LabelPrefixClusterPolicy + "deny-privileged": "3"},
		ruleResult(SourceKyverno, "deny-privileged", "check-priv", openreports.StatusFail, "privileged containers are blocked", 150),
	)
	byRule, byResource := AggregateByRuleAndResource(pod1, pod2, node)

	// Namespaced rule row: two distinct resources, one fail and one pass; the
	// most recent observation (pass) provides the last reason.
	namespaced := findRuleRow(t, byRule, "team-a", "team-a/require-label", "check-label", "10")
	assert.Equal(t, SourceKyverno, namespaced.Source)
	assert.Equal(t, StatusCounts{Pass: 1, Fail: 1}, namespaced.Counts)
	assert.Equal(t, openreportsv1alpha1.Result(openreports.StatusPass), namespaced.LastResult)
	assert.Equal(t, "labels ok", namespaced.LastReason)
	assert.Equal(t, int64(200), namespaced.LastTimestamp)

	// Cluster-scoped policy row: empty namespace, revision read from the cpol label.
	cluster := findRuleRow(t, byRule, "", "deny-privileged", "check-priv", "3")
	assert.Equal(t, StatusCounts{Fail: 1}, cluster.Counts)
	assert.Equal(t, "privileged containers are blocked", cluster.LastReason)

	// Resource rows distinguish resources by UID and namespace.
	assert.Equal(t, StatusCounts{Fail: 1}, findResourceRow(t, byResource, "team-a", "uid-1").Counts)
	assert.Equal(t, StatusCounts{Pass: 1}, findResourceRow(t, byResource, "team-a", "uid-2").Counts)
	clusterResource := findResourceRow(t, byResource, "", "uid-3")
	assert.Equal(t, StatusCounts{Fail: 1}, clusterResource.Counts)
	assert.Equal(t, "Node", clusterResource.ResourceKind)
}

// TestAggregate_PolicyRevisionSeparatesRows proves results produced against
// different policy resource versions are never merged, even for the same
// resource and rule.
func TestAggregate_PolicyRevisionSeparatesRows(t *testing.T) {
	t.Parallel()
	before := buildEphemeralReport(t, false, "ephr-before", "team-a", "pod-1", "uid-1", "Pod", false,
		map[string]string{LabelPrefixPolicy + "require-label": "10"},
		ruleResult(SourceKyverno, "team-a/require-label", "check-label", openreports.StatusFail, "missing app label", 100),
	)
	after := buildEphemeralReport(t, false, "ephr-after", "team-a", "pod-1", "uid-1", "Pod", false,
		map[string]string{LabelPrefixPolicy + "require-label": "11"},
		ruleResult(SourceKyverno, "team-a/require-label", "check-label", openreports.StatusPass, "labels ok", 200),
	)
	byRule, byResource := AggregateByRuleAndResource(before, after)
	assert.Len(t, byRule, 2)
	assert.Equal(t, StatusCounts{Fail: 1}, findRuleRow(t, byRule, "team-a", "team-a/require-label", "check-label", "10").Counts)
	assert.Equal(t, StatusCounts{Pass: 1}, findRuleRow(t, byRule, "team-a", "team-a/require-label", "check-label", "11").Counts)
	// the single resource carries two distinct revision outcomes
	resource := findResourceRow(t, byResource, "team-a", "uid-1")
	assert.Equal(t, StatusCounts{Pass: 1, Fail: 1}, resource.Counts)
}

// TestAggregate_InformerReconnectDoesNotDoubleCount simulates an informer
// reconnect re-listing the same reports and an overlap between ephemeral and
// permanent reports for the same resource: counts must stay identical and the
// most recent observation wins.
func TestAggregate_InformerReconnectDoesNotDoubleCount(t *testing.T) {
	t.Parallel()
	original := buildEphemeralReport(t, false, "ephr-1", "team-a", "pod-1", "uid-1", "Pod", false,
		map[string]string{LabelPrefixPolicy + "require-label": "10"},
		ruleResult(SourceKyverno, "team-a/require-label", "check-label", openreports.StatusFail, "missing app label", 100),
	)
	relisted := buildEphemeralReport(t, false, "ephr-1-relisted", "team-a", "pod-1", "uid-1", "Pod", false,
		map[string]string{LabelPrefixPolicy + "require-label": "10"},
		ruleResult(SourceKyverno, "team-a/require-label", "check-label", openreports.StatusFail, "missing app label", 100),
	)
	overlap := buildEphemeralReport(t, false, "polr-1", "team-a", "pod-1", "uid-1", "Pod", false,
		map[string]string{LabelPrefixPolicy + "require-label": "10"},
		ruleResult(SourceKyverno, "team-a/require-label", "check-label", openreports.StatusPass, "labels ok", 150),
	)
	once, resourcesOnce := AggregateByRuleAndResource(original)
	relistedOnly, resourcesRelistedOnly := AggregateByRuleAndResource(original, relisted)
	replayed, resourcesReplayed := AggregateByRuleAndResource(original, relisted, overlap)
	require.Len(t, once, 1)
	require.Len(t, relistedOnly, 1)
	require.Len(t, replayed, 1)
	// an informer reconnect re-listing the same objects must not double count
	assert.Equal(t, once[0].Counts, relistedOnly[0].Counts)
	assert.Equal(t, StatusCounts{Fail: 1}, once[0].Counts)
	// a genuinely newer overlapping observation wins and is still counted once
	assert.Equal(t, StatusCounts{Pass: 1}, replayed[0].Counts)
	assert.Equal(t, openreportsv1alpha1.Result(openreports.StatusPass), replayed[0].LastResult)
	assert.Equal(t, "labels ok", replayed[0].LastReason)
	assert.Len(t, resourcesReplayed, 1)
	assert.Equal(t, resourcesOnce[0].Counts, resourcesRelistedOnly[0].Counts)
	assert.Equal(t, StatusCounts{Pass: 1}, resourcesReplayed[0].Counts)
}

// TestAggregate_DeletedResourceIgnored proves reports that are being deleted
// (a deleted resource whose reports await garbage collection) are not counted.
func TestAggregate_DeletedResourceIgnored(t *testing.T) {
	t.Parallel()
	tombstone := buildEphemeralReport(t, false, "ephr-deleted", "team-a", "pod-deleted", "uid-gone", "Pod", true,
		map[string]string{LabelPrefixPolicy + "require-label": "10"},
		ruleResult(SourceKyverno, "team-a/require-label", "check-label", openreports.StatusFail, "missing app label", 100),
	)
	live := buildEphemeralReport(t, false, "ephr-live", "team-a", "pod-live", "uid-live", "Pod", false,
		map[string]string{LabelPrefixPolicy + "require-label": "10"},
		ruleResult(SourceKyverno, "team-a/require-label", "check-label", openreports.StatusPass, "labels ok", 200),
	)
	byRule, byResource := AggregateByRuleAndResource(tombstone, live)
	require.Len(t, byRule, 1)
	assert.Equal(t, StatusCounts{Pass: 1}, byRule[0].Counts)
	assert.Len(t, byResource, 1)
	assert.Equal(t, "uid-live", string(byResource[0].ResourceUID))

	// aggregating only tombstones yields nothing
	emptyRules, emptyResources := AggregateByRuleAndResource(tombstone)
	assert.Empty(t, emptyRules)
	assert.Empty(t, emptyResources)
}

func TestPolicyRevision(t *testing.T) {
	t.Parallel()
	report := &reportsv1.EphemeralReport{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
		LabelPrefixPolicy + "require-label":               "10",
		LabelPrefixClusterPolicy + "deny-privileged":      "3",
		LabelPrefixValidatingPolicy + "check-replicas":    "7",
		LabelPrefixValidatingAdmissionPolicy + "vap-rule": "2",
	}}}
	assert.Equal(t, "10", PolicyRevision(report, SourceKyverno, "team-a/require-label"))
	assert.Equal(t, "3", PolicyRevision(report, SourceKyverno, "deny-privileged"))
	assert.Equal(t, "7", PolicyRevision(report, SourceValidatingPolicy, "check-replicas"))
	assert.Equal(t, "2", PolicyRevision(report, SourceValidatingAdmissionPolicy, "vap-rule"))
	// unknown policy / source falls back to any matching policy-domain label
	assert.Equal(t, "10", PolicyRevision(report, SourceMutatingPolicy, "require-label"))
	// missing revision and nil reports are tolerated
	assert.Equal(t, "", PolicyRevision(report, SourceKyverno, "does-not-exist"))
	assert.Equal(t, "", PolicyRevision(nil, SourceKyverno, "require-label"))
}

func TestPaginate_NoOverlapAcrossPages(t *testing.T) {
	t.Parallel()
	rows := make([]RuleAggregationRow, 5)
	for i := range rows {
		rows[i] = RuleAggregationRow{Policy: "policy", Rule: "rule", PolicyRevision: string(rune('0' + i))}
	}
	var collected []RuleAggregationRow
	continueToken := ""
	for page := 0; ; page++ {
		items, next, err := Paginate(rows, 2, continueToken)
		require.NoError(t, err)
		collected = append(collected, items...)
		if next == "" {
			break
		}
		continueToken = next
	}
	assert.Equal(t, rows, collected, "paged rows must equal the full set without duplicates")

	// invalid / out-of-range tokens fail
	_, _, err := Paginate(rows, 2, "not-base64!!")
	assert.Error(t, err)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(len(rows) + 1)))
	_, _, err = Paginate(rows, 2, encoded)
	assert.Error(t, err)

	// non-positive limits return everything
	all, next, err := Paginate(rows, 0, "")
	require.NoError(t, err)
	assert.Len(t, all, len(rows))
	assert.Empty(t, next)
}

func TestAggregateEngineResponses_NamespaceRevisionAndUID(t *testing.T) {
	t.Parallel()
	policy := engineapi.NewKyvernoPolicy(&kyvernov1.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "team-a",
			Name:            "require-label",
			ResourceVersion: "4",
		},
	})
	resource := unstructured.Unstructured{}
	resource.SetAPIVersion("v1")
	resource.SetKind("Pod")
	resource.SetNamespace("team-a")
	resource.SetName("pod-7")
	resource.SetUID("uid-7")
	policyResponse := engineapi.NewPolicyResponse()
	policyResponse.Add(engineapi.NewExecutionStats(time.Unix(100, 0), time.Unix(100, 0)),
		*engineapi.RulePass("check-label", engineapi.Validation, "labels ok", nil),
		*engineapi.RuleSkip("guard-rule", engineapi.Validation, "not applicable", nil),
		*engineapi.RuleError("broken-rule", engineapi.Validation, "eval failed", assert.AnError, nil),
	)
	response := engineapi.NewEngineResponse(resource, policy, nil).WithPolicyResponse(policyResponse)

	byRule, byResource := AggregateEngineResponses(response, response)
	// replaying the same engine response (e.g. after an informer reconnect)
	// must not double count: AggregateEngineResponses received the response
	// twice, but the same (rule x resource x revision) fact is deduplicated.
	for _, row := range byRule {
		assert.Equal(t, 1, row.Counts.Total(), "rule %q was double counted", row.Rule)
		assert.Equal(t, "team-a", row.Namespace)
		assert.Equal(t, "4", row.PolicyRevision)
	}
	pass := findRuleRow(t, byRule, "team-a", "team-a/require-label", "check-label", "4")
	assert.Equal(t, StatusCounts{Pass: 1}, pass.Counts)
	assert.Equal(t, "labels ok", pass.LastReason)
	skip := findRuleRow(t, byRule, "team-a", "team-a/require-label", "guard-rule", "4")
	assert.Equal(t, StatusCounts{Skip: 1}, skip.Counts)
	failed := findRuleRow(t, byRule, "team-a", "team-a/require-label", "broken-rule", "4")
	assert.Equal(t, StatusCounts{Error: 1}, failed.Counts)
	assert.Contains(t, failed.LastReason, "eval failed")

	require.Len(t, byResource, 1)
	resourceRow := byResource[0]
	assert.Equal(t, "team-a", resourceRow.Namespace)
	assert.Equal(t, "uid-7", string(resourceRow.ResourceUID))
	assert.Equal(t, StatusCounts{Pass: 1, Skip: 1, Error: 1}, resourceRow.Counts)
}
