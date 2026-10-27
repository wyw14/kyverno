package aggregate

import (
	reportsv1 "github.com/kyverno/kyverno/api/reports/v1"
	reportutils "github.com/kyverno/kyverno/pkg/utils/report"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// QueryRuleAndResourceAggregations answers the policy report by-rule and
// by-resource aggregation query over the given reports.
//
// Reports are first grouped by resource UID and reduced with the exact same
// active-policy filtering and last-write-wins merge MergeReports performs in
// backReconcile (via AggregateResults). Consequently:
//   - overlapping permanent and ephemeral reports and reports re-delivered by
//     an informer reconnect (re-list) collapse onto a single observation and
//     are never counted twice;
//   - results whose policy/rule is no longer active (for example a policy was
//     deleted, or a deleted resource left stale reports behind) are dropped
//     before counting;
//   - reports being deleted are ignored.
//
// The merged results are then folded by reportutils.AggregateByRuleAndResource,
// which keeps results produced at different policy revisions and against
// different resource UIDs in distinct rows.
func QueryRuleAndResourceAggregations(maps Maps, reports ...reportsv1.ReportInterface) ([]reportutils.RuleAggregationRow, []reportutils.ResourceAggregationRow) {
	groups := map[types.UID][]reportsv1.ReportInterface{}
	for _, report := range reports {
		if report == nil || report.GetDeletionTimestamp() != nil {
			continue
		}
		uid := reportutils.ResolveResourceUID(report)
		if uid == "" {
			continue
		}
		groups[uid] = append(groups[uid], report)
	}
	merged := make([]reportsv1.ReportInterface, 0, len(groups))
	for uid, grouped := range groups {
		results := AggregateResults(maps, uid, grouped...)
		if len(results) == 0 {
			continue
		}
		merged = append(merged, newMergedCarrier(uid, grouped, results))
	}
	return reportutils.AggregateByRuleAndResource(merged...)
}

// newMergedCarrier builds an in-memory report carrying the merged results of
// one resource group, together with the union of labels/annotations the
// aggregation needs (policy revision labels and resource coordinates).
func newMergedCarrier(uid types.UID, grouped []reportsv1.ReportInterface, results []openreportsv1alpha1.ReportResult) reportsv1.ReportInterface {
	namespace, name := mergedResourceCoordinates(grouped)
	var carrier reportsv1.ReportInterface
	if namespace == "" {
		carrier = &reportsv1.ClusterEphemeralReport{}
	} else {
		carrier = &reportsv1.EphemeralReport{}
		carrier.SetNamespace(namespace)
	}
	labels := map[string]string{}
	annotations := map[string]string{}
	for _, report := range grouped {
		for key, value := range report.GetLabels() {
			labels[key] = value
		}
		for key, value := range report.GetAnnotations() {
			annotations[key] = value
		}
	}
	carrier.SetLabels(labels)
	carrier.SetAnnotations(annotations)
	reportutils.SetResourceUid(carrier, uid)
	reportutils.SetResourceNamespaceAndName(carrier, namespace, name)
	carrier.SetResults(results)
	return carrier
}

// mergedResourceCoordinates returns the first non-empty resource namespace and
// name recorded across the grouped reports, falling back to the namespace of a
// namespaced report object.
func mergedResourceCoordinates(grouped []reportsv1.ReportInterface) (string, string) {
	namespace, name := "", ""
	for _, report := range grouped {
		if report == nil {
			continue
		}
		if reportNamespace, reportName := reportutils.GetResourceNamespaceAndName(report); reportNamespace != "" || reportName != "" {
			if namespace == "" {
				namespace = reportNamespace
			}
			if name == "" {
				name = reportName
			}
		}
		if namespace == "" && report.GetNamespace() != "" {
			namespace = report.GetNamespace()
		}
	}
	return namespace, name
}
