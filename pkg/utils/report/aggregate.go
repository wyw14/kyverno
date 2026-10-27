package report

import (
	"cmp"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"

	reportsv1 "github.com/kyverno/kyverno/api/reports/v1"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"github.com/kyverno/kyverno/pkg/openreports"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

// StatusCounts holds the number of de-duplicated observations per report
// result status.
type StatusCounts struct {
	// Pass is the number of passing observations.
	Pass int
	// Fail is the number of failing observations.
	Fail int
	// Warn is the number of non-scored failing observations.
	Warn int
	// Error is the number of observations that could not be evaluated.
	Error int
	// Skip is the number of skipped observations.
	Skip int
}

// Total returns the number of de-duplicated observations counted across all
// statuses.
func (c StatusCounts) Total() int {
	return c.Pass + c.Fail + c.Warn + c.Error + c.Skip
}

func (c *StatusCounts) add(status openreportsv1alpha1.Result) {
	switch status {
	case openreports.StatusPass:
		c.Pass++
	case openreports.StatusFail:
		c.Fail++
	case openreports.StatusWarn:
		c.Warn++
	case openreports.StatusError:
		c.Error++
	case openreports.StatusSkip:
		c.Skip++
	}
}

// RuleAggregationRow is one row of the by-rule policy report query: how many
// distinct resources (per status) a policy rule was evaluated against at a
// given policy revision in a given namespace, and the most recent reason the
// engine reported.
type RuleAggregationRow struct {
	// Namespace is the namespace of the counted resources. Empty for
	// cluster-scoped resources and cluster-wide policies.
	Namespace string
	// Source is the policy engine source that produced the results.
	Source string
	// Policy is the policy key (namespace/name for namespaced policies, name
	// for cluster-scoped policies).
	Policy string
	// Rule is the rule name within the policy.
	Rule string
	// PolicyRevision is the policy resource version the results were produced
	// with, as recorded by SetPolicyLabel. Results produced at different policy
	// revisions are never merged into the same row.
	PolicyRevision string
	// Counts contains the number of distinct resources per result status.
	Counts StatusCounts
	// LastResult is the status of the most recent observation in the row.
	LastResult openreportsv1alpha1.Result
	// LastReason is the message (ReportResult.Description) of the most recent
	// observation in the row.
	LastReason string
	// LastTimestamp is the unix timestamp (seconds) of the most recent
	// observation in the row.
	LastTimestamp int64
}

// ResourceAggregationRow is one row of the by-resource policy report query:
// how many distinct policy rule outcomes (per status) were recorded for a
// resource, and the most recent reason the engine reported.
type ResourceAggregationRow struct {
	// Namespace is the resource namespace. Empty for cluster-scoped resources.
	Namespace string
	// ResourceUID is the resource UID.
	ResourceUID types.UID
	// ResourceName is the resource name when known.
	ResourceName string
	// ResourceKind is the resource kind when known.
	ResourceKind string
	// Counts contains the number of distinct (policy, rule, revision) outcomes
	// per result status.
	Counts StatusCounts
	// LastResult is the status of the most recent observation in the row.
	LastResult openreportsv1alpha1.Result
	// LastReason is the message (ReportResult.Description) of the most recent
	// observation in the row.
	LastReason string
	// LastTimestamp is the unix timestamp (seconds) of the most recent
	// observation in the row.
	LastTimestamp int64
}

// observation is the internal, fully-resolved representation of one report
// result against one resource.
type observation struct {
	source    string
	namespace string
	policy    string
	rule      string
	revision  string
	uid       types.UID
	name      string
	kind      string
	status    openreportsv1alpha1.Result
	reason    string
	timestamp int64
}

// identity keys every distinct (rule x resource x policy revision)
// observation. Two observations with the same identity describe the same fact,
// so re-delivering it (permanent and ephemeral reports overlapping, or an
// informer reconnect re-listing the same objects) must not be counted twice.
func (o observation) identity() string {
	return strings.Join([]string{o.source, o.namespace, o.policy, o.rule, o.revision, string(o.uid)}, "\x00")
}

func isKnownStatus(status openreportsv1alpha1.Result) bool {
	switch status {
	case openreports.StatusPass, openreports.StatusFail, openreports.StatusWarn, openreports.StatusError, openreports.StatusSkip:
		return true
	}
	return false
}

// ruleGroup accumulates the latest observation of each resource for a
// (namespace, source, policy, rule, revision) tuple.
type ruleGroup struct {
	row       RuleAggregationRow
	resources map[types.UID]observation
}

// resourceGroup accumulates the latest observation of each
// (policy, rule, revision) outcome for a (namespace, resource UID) tuple.
type resourceGroup struct {
	row      ResourceAggregationRow
	outcomes map[string]observation
}

func foldObservations(observations []observation) ([]RuleAggregationRow, []ResourceAggregationRow) {
	// De-duplicate first: same identity keeps the most recent observation
	// (strictly later timestamp wins, first-seen wins a tie, matching
	// MergeReports), so replayed inputs collapse onto a single fact.
	deduped := map[string]observation{}
	for _, o := range observations {
		if !isKnownStatus(o.status) || o.uid == "" {
			continue
		}
		key := o.identity()
		if current, exists := deduped[key]; !exists || o.timestamp > current.timestamp {
			deduped[key] = o
		}
	}
	rules := map[string]*ruleGroup{}
	resources := map[string]*resourceGroup{}
	for _, o := range deduped {
		ruleKey := strings.Join([]string{o.namespace, o.source, o.policy, o.rule, o.revision}, "\x00")
		group, exists := rules[ruleKey]
		if !exists {
			group = &ruleGroup{
				row: RuleAggregationRow{
					Namespace:      o.namespace,
					Source:         o.source,
					Policy:         o.policy,
					Rule:           o.rule,
					PolicyRevision: o.revision,
				},
				resources: map[types.UID]observation{},
			}
			rules[ruleKey] = group
		}
		group.resources[o.uid] = o
		if o.timestamp >= group.row.LastTimestamp {
			group.row.LastTimestamp = o.timestamp
			group.row.LastResult = o.status
			group.row.LastReason = o.reason
		}
		resourceKey := strings.Join([]string{o.namespace, string(o.uid)}, "\x00")
		resourceGroupEntry, exists := resources[resourceKey]
		if !exists {
			resourceGroupEntry = &resourceGroup{
				row: ResourceAggregationRow{
					Namespace:    o.namespace,
					ResourceUID:  o.uid,
					ResourceName: o.name,
					ResourceKind: o.kind,
				},
				outcomes: map[string]observation{},
			}
			resources[resourceKey] = resourceGroupEntry
		} else {
			if resourceGroupEntry.row.ResourceName == "" {
				resourceGroupEntry.row.ResourceName = o.name
			}
			if resourceGroupEntry.row.ResourceKind == "" {
				resourceGroupEntry.row.ResourceKind = o.kind
			}
		}
		outcomeKey := strings.Join([]string{o.source, o.policy, o.rule, o.revision}, "\x00")
		resourceGroupEntry.outcomes[outcomeKey] = o
		if o.timestamp >= resourceGroupEntry.row.LastTimestamp {
			resourceGroupEntry.row.LastTimestamp = o.timestamp
			resourceGroupEntry.row.LastResult = o.status
			resourceGroupEntry.row.LastReason = o.reason
		}
	}
	byRule := make([]RuleAggregationRow, 0, len(rules))
	for _, group := range rules {
		for _, o := range group.resources {
			group.row.Counts.add(o.status)
		}
		byRule = append(byRule, group.row)
	}
	slices.SortFunc(byRule, func(a, b RuleAggregationRow) int {
		if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Source, b.Source); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Policy, b.Policy); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Rule, b.Rule); c != 0 {
			return c
		}
		return cmp.Compare(a.PolicyRevision, b.PolicyRevision)
	})
	byResource := make([]ResourceAggregationRow, 0, len(resources))
	for _, group := range resources {
		for _, o := range group.outcomes {
			group.row.Counts.add(o.status)
		}
		byResource = append(byResource, group.row)
	}
	slices.SortFunc(byResource, func(a, b ResourceAggregationRow) int {
		if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		if c := cmp.Compare(a.ResourceName, b.ResourceName); c != 0 {
			return c
		}
		return cmp.Compare(string(a.ResourceUID), string(b.ResourceUID))
	})
	return byRule, byResource
}

// observationsFromReport resolves every result of a report into observations
// against the resource(s) the report refers to.
func observationsFromReport(report reportsv1.ReportInterface) []observation {
	if report == nil || report.GetDeletionTimestamp() != nil {
		return nil
	}
	metaNamespace, metaName := GetResourceNamespaceAndName(report)
	metaKind := report.GetLabels()[LabelResourceKind]
	fallbackUID := GetResourceUid(report)
	if fallbackUID == "" {
		for _, ref := range report.GetOwnerReferences() {
			if ref.UID != "" {
				fallbackUID = ref.UID
				break
			}
		}
	}
	observations := []observation{}
	for _, result := range report.GetResults() {
		revision := PolicyRevision(report, result.Source, result.Policy)
		if len(result.Subjects) > 0 {
			for _, subject := range result.Subjects {
				namespace := subject.Namespace
				if namespace == "" {
					namespace = metaNamespace
				}
				observations = append(observations, observation{
					source:    result.Source,
					namespace: namespace,
					policy:    result.Policy,
					rule:      result.Rule,
					revision:  revision,
					uid:       subject.UID,
					name:      subject.Name,
					kind:      subject.Kind,
					status:    result.Result,
					reason:    result.Description,
					timestamp: result.Timestamp.Seconds,
				})
			}
		} else {
			uid := fallbackUID
			if uid == "" {
				// Permanent policy reports are named after the resource UID.
				uid = types.UID(report.GetName())
			}
			namespace := metaNamespace
			if namespace == "" {
				namespace = report.GetNamespace()
			}
			observations = append(observations, observation{
				source:    result.Source,
				namespace: namespace,
				policy:    result.Policy,
				rule:      result.Rule,
				revision:  revision,
				uid:       uid,
				name:      metaName,
				kind:      metaKind,
				status:    result.Result,
				reason:    result.Description,
				timestamp: result.Timestamp.Seconds,
			})
		}
	}
	return observations
}

// AggregateByRuleAndResource answers the policy report aggregation query over
// the given reports. It returns:
//   - rows grouped by (resource namespace, source, policy, rule, policy
//     revision), counting distinct resources per pass/fail/warn/error/skip
//     status and carrying the most recent reason;
//   - rows grouped by (resource namespace, resource UID), counting distinct
//     (policy, rule, revision) outcomes per status and carrying the most recent
//     reason.
//
// Results are de-duplicated by (source, namespace, policy, rule, policy
// revision, resource UID): the same result present in overlapping permanent
// and ephemeral reports, or re-delivered after an informer reconnect (re-list),
// is counted exactly once, keeping the most recent observation. Reports that
// are being deleted are ignored, so resources whose reports are awaiting
// garbage collection are not counted. Returned rows are sorted by their key so
// callers can page over them deterministically with Paginate.
func AggregateByRuleAndResource(reports ...reportsv1.ReportInterface) ([]RuleAggregationRow, []ResourceAggregationRow) {
	observations := make([]observation, 0)
	for _, report := range reports {
		observations = append(observations, observationsFromReport(report)...)
	}
	return foldObservations(observations)
}

// AggregateEngineResponses builds the same by-rule and by-resource aggregation
// rows directly from engine evaluations. Rows are keyed by the evaluated
// resource namespace and UID and the policy resource version, and duplicate
// rule responses are collapsed by the engine's AggregateRuleResponses helper.
func AggregateEngineResponses(responses ...engineapi.EngineResponse) ([]RuleAggregationRow, []ResourceAggregationRow) {
	observations := make([]observation, 0)
	for _, response := range responses {
		policy := response.Policy()
		if policy == nil || len(response.PolicyResponse.Rules) == 0 {
			continue
		}
		resource := corev1.ObjectReference{
			APIVersion: response.Resource.GetAPIVersion(),
			Kind:       response.Resource.GetKind(),
			Namespace:  response.Resource.GetNamespace(),
			Name:       response.Resource.GetName(),
			UID:        response.Resource.GetUID(),
		}
		mapped := make(map[string]openreportsv1alpha1.ReportResult, len(response.PolicyResponse.Rules))
		for i := range response.PolicyResponse.Rules {
			rule := response.PolicyResponse.Rules[i]
			mapped[rule.Name()] = ToPolicyReportResult(policy, rule, &resource)
		}
		for _, outcome := range engineapi.AggregateRuleResponses(response.PolicyResponse.Rules...) {
			result, exists := mapped[outcome.Name]
			if !exists {
				continue
			}
			timestamp := result.Timestamp.Seconds
			if !outcome.ObservedAt.IsZero() {
				timestamp = outcome.ObservedAt.Unix()
			}
			observations = append(observations, observation{
				source:    result.Source,
				namespace: resource.Namespace,
				policy:    result.Policy,
				rule:      result.Rule,
				revision:  policy.GetResourceVersion(),
				uid:       resource.UID,
				name:      resource.Name,
				kind:      resource.Kind,
				status:    result.Result,
				reason:    result.Description,
				timestamp: timestamp,
			})
		}
	}
	return foldObservations(observations)
}

// ResolveResourceUID returns the UID of the resource a report refers to. It
// checks, in order, the UID of the first result subject, the
// audit.kyverno.io/resource.uid label, the first owner reference, and finally
// the report name (permanent policy reports are named after the resource UID).
func ResolveResourceUID(report reportsv1.ReportInterface) types.UID {
	if report == nil {
		return ""
	}
	for _, result := range report.GetResults() {
		for _, subject := range result.Subjects {
			if subject.UID != "" {
				return subject.UID
			}
		}
	}
	if uid := GetResourceUid(report); uid != "" {
		return uid
	}
	for _, ref := range report.GetOwnerReferences() {
		if ref.UID != "" {
			return ref.UID
		}
	}
	return types.UID(report.GetName())
}

// policyRevisionLabelPrefixes returns the policy label prefixes that may carry
// the resource version of the policy that produced a result with the given
// source (see SetPolicyLabel).
func policyRevisionLabelPrefixes(source, policyKey string) []string {
	_, name, err := cache.SplitMetaNamespaceKey(policyKey)
	namespaced := err == nil && name != policyKey
	switch source {
	case SourceKyverno:
		if namespaced {
			return []string{LabelPrefixPolicy, LabelPrefixClusterPolicy}
		}
		return []string{LabelPrefixClusterPolicy, LabelPrefixPolicy}
	case SourceValidatingPolicy:
		return []string{LabelPrefixValidatingPolicy}
	case SourceImageValidatingPolicy:
		return []string{LabelPrefixImageValidatingPolicy}
	case SourceGeneratingPolicy:
		return []string{LabelPrefixGeneratingPolicy}
	case SourceMutatingPolicy:
		return []string{LabelPrefixMutatingPolicy}
	case SourceValidatingAdmissionPolicy:
		return []string{LabelPrefixValidatingAdmissionPolicy}
	case SourceMutatingAdmissionPolicy:
		return []string{LabelPrefixMutatingAdmissionPolicy}
	}
	return nil
}

// PolicyRevision returns the resource version of the policy that produced the
// given result, as recorded on the report labels by SetPolicyLabel
// ("<policy-domain>/<policy-name>" = "<resourceVersion>"). It returns an empty
// string when the report carries no revision label for the policy.
func PolicyRevision(report metav1.Object, source, policy string) string {
	if report == nil {
		return ""
	}
	labels := report.GetLabels()
	if len(labels) == 0 || policy == "" {
		return ""
	}
	_, name, err := cache.SplitMetaNamespaceKey(policy)
	if err != nil || name == "" {
		name = policy
	}
	for _, prefix := range policyRevisionLabelPrefixes(source, policy) {
		if revision := labels[prefix+name]; revision != "" {
			return revision
		}
	}
	// Fallback: a policy-domain label whose suffix matches the policy name.
	for key, revision := range labels {
		if !IsPolicyLabel(key) {
			continue
		}
		for _, prefix := range allPolicyLabelPrefixes {
			if strings.TrimPrefix(key, prefix) == name && revision != "" {
				return revision
			}
		}
	}
	return ""
}

// allPolicyLabelPrefixes lists every policy-domain label prefix that may carry
// a policy resource version, for the generic PolicyRevision fallback.
var allPolicyLabelPrefixes = []string{
	LabelPrefixClusterPolicy,
	LabelPrefixPolicy,
	LabelPrefixValidatingPolicy,
	LabelPrefixImageValidatingPolicy,
	LabelPrefixGeneratingPolicy,
	LabelPrefixMutatingPolicy,
	LabelPrefixDeletingPolicy,
	LabelPrefixValidatingAdmissionPolicy,
	LabelPrefixMutatingAdmissionPolicy,
}

// Paginate returns a stable page of the given (pre-sorted) rows and an opaque
// continuation token. Pages never overlap, so walking every page counts each
// row exactly once. A non-positive limit returns all remaining rows with an
// empty token. An invalid or out-of-range token returns an error.
func Paginate[T any](rows []T, limit int, continueToken string) ([]T, string, error) {
	offset := 0
	if continueToken != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(continueToken)
		if err != nil {
			return nil, "", fmt.Errorf("invalid continue token %q: %w", continueToken, err)
		}
		offset, err = strconv.Atoi(string(decoded))
		if err != nil || offset < 0 {
			return nil, "", fmt.Errorf("invalid continue token %q", continueToken)
		}
	}
	if offset > len(rows) {
		return nil, "", fmt.Errorf("continue token %q is out of range", continueToken)
	}
	if limit <= 0 {
		return rows[offset:], "", nil
	}
	end := offset + limit
	if end >= len(rows) {
		return rows[offset:], "", nil
	}
	next := base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	return rows[offset:end], next, nil
}
