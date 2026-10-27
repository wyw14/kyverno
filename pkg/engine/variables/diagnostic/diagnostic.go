// Package diagnostic provides read-only Kyverno policy variable expansion diagnostics.
//
// Diagnostics expand every {{ <jmespath> }} variable used by a policy rule against a
// policy context built for a specific resource and report, for each occurrence:
//
//   - where the variable is used in the rule (a JSON pointer),
//   - where its value is expected to come from (request.object, a context entry, a
//     foreach element, ...),
//   - the JMESPath expression that was evaluated,
//   - the JSON type of the resolved value and how it would be converted when the rule
//     is substituted (native value, JSON-marshaled text or raw string),
//   - why a variable could not be resolved (missing path, invalid expression, denied
//     API call, failed context entry, unbound foreach element, ...).
//
// Diagnostics never apply mutations and never create or update resources: mutate and
// generate rule handlers are not invoked. Context entries (ConfigMap, APICall,
// Variable, ...) are loaded through the same read-only loaders the engine uses for
// variable resolution. Every rule gets its own, freshly built policy context, so the
// context entries and foreach element bindings of one rule can never leak into the
// diagnostics of another rule evaluated against the same resource.
package diagnostic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-logr/logr"
	gojmespath "github.com/kyverno/go-jmespath"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	kyvernov2 "github.com/kyverno/kyverno/api/kyverno/v2"
	"github.com/kyverno/kyverno/pkg/config"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	enginecontext "github.com/kyverno/kyverno/pkg/engine/context"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"github.com/kyverno/kyverno/pkg/engine/jsonutils"
	"github.com/kyverno/kyverno/pkg/engine/policycontext"
	engineutils "github.com/kyverno/kyverno/pkg/engine/utils"
	"github.com/kyverno/kyverno/pkg/logging"
	"github.com/kyverno/kyverno/pkg/utils/jsonpointer"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// VariableSource identifies where a variable value is expected to come from.
type VariableSource string

const (
	// SourceResource is a variable read from the admission resource
	// (request.object or request.oldObject).
	SourceResource VariableSource = "request.object"
	// SourceRequest is a variable read from the admission request other than the
	// resource itself (request.operation, request.namespace, request.userInfo, ...).
	SourceRequest VariableSource = "request"
	// SourceTarget is a variable read from the explicit foreach target.
	SourceTarget VariableSource = "target"
	// SourceServiceAccount is a serviceAccountName/serviceAccountNamespace variable.
	SourceServiceAccount VariableSource = "serviceaccount"
	// SourceImages is an images/image variable.
	SourceImages VariableSource = "images"
	// SourceContextEntry is a variable backed by a rule or foreach context entry
	// (ConfigMap, APICall, Variable, GlobalReference, ImageRegistry).
	SourceContextEntry VariableSource = "context-entry"
	// SourceForEachElement is an element/elementIndex (or element0, elementIndex1,
	// ...) variable bound by a foreach iterator.
	SourceForEachElement VariableSource = "foreach-element"
	// SourceFunction is a pure JMESPath expression with no context root
	// (literals, functions, multi-select hashes, ...).
	SourceFunction VariableSource = "function"
	// SourceUnknown is a variable whose root could not be attributed to a known
	// source or a declared context entry.
	SourceUnknown VariableSource = "unknown"
)

// ResolutionStatus is the outcome of resolving a variable or loading a context entry.
type ResolutionStatus string

const (
	// StatusResolved means the JMESPath expression evaluated without error.
	StatusResolved ResolutionStatus = "resolved"
	// StatusNotFound means the JMESPath path does not exist in the context. This
	// maps to go-jmespath NotFoundError.
	StatusNotFound ResolutionStatus = "not-found"
	// StatusInvalidExpression means the JMESPath expression could not be compiled.
	StatusInvalidExpression ResolutionStatus = "invalid-expression"
	// StatusPermissionDenied means the context data could not be fetched because the
	// API server rejected the call (401/403).
	StatusPermissionDenied ResolutionStatus = "permission-denied"
	// StatusContextLoadError means a context entry failed to load for a reason
	// other than missing RBAC permissions.
	StatusContextLoadError ResolutionStatus = "context-load-error"
	// StatusElementNotBound means the variable belongs to a foreach scope whose
	// list expression could not be evaluated, so no element could be bound.
	StatusElementNotBound ResolutionStatus = "element-not-bound"
	// StatusQueryError is any other JMESPath evaluation error.
	StatusQueryError ResolutionStatus = "query-error"
	// StatusDisabled means the data source required to resolve the variable is not
	// configured (no context loader, client or resolver).
	StatusDisabled ResolutionStatus = "disabled"
)

// ConversionKind describes how a resolved value is converted when it is substituted
// into the rule document.
type ConversionKind string

const (
	// ConversionNative means the variable occupies the whole string, so the resolved
	// value keeps its native JSON type (number, boolean, object, array, ...).
	ConversionNative ConversionKind = "native"
	// ConversionJSON means the non-string value is embedded in a larger string and
	// is therefore JSON-marshaled into text.
	ConversionJSON ConversionKind = "json"
	// ConversionString means a string value is embedded verbatim into the surrounding
	// text.
	ConversionString ConversionKind = "string"
	// ConversionNone means the variable was not resolved, so no conversion happens.
	ConversionNone ConversionKind = "none"
)

// ElementBinding identifies one concrete foreach iteration: the list expression that
// produced the element and the index of the bound element.
type ElementBinding struct {
	// List is the foreach list JMESPath expression.
	List string `json:"list"`
	// Index is the index of the element within the evaluated list.
	Index int `json:"index"`
}

// VariableDiagnostic is the expansion result of a single {{ ... }} occurrence.
type VariableDiagnostic struct {
	// Expression is the trimmed JMESPath expression found inside {{ ... }}.
	Expression string `json:"expression"`
	// Location is the RFC6901 JSON pointer of the string (or map key) inside the rule
	// document where the variable is used.
	Location string `json:"location"`
	// Source is where the value is expected to come from.
	Source VariableSource `json:"source"`
	// ContextEntry is the context entry name when Source is SourceContextEntry.
	ContextEntry string `json:"contextEntry,omitempty"`
	// Status is the resolution outcome.
	Status ResolutionStatus `json:"status"`
	// ValueType is the JSON type of the resolved value
	// (string, number, boolean, object, array, null).
	ValueType string `json:"valueType,omitempty"`
	// Value is the resolved value.
	Value interface{} `json:"value,omitempty"`
	// Conversion describes how the value would be embedded during substitution.
	Conversion ConversionKind `json:"conversion"`
	// Shallow reports a {{- ... }} (shallow substitution) marker.
	Shallow bool `json:"shallow,omitempty"`
	// Reason explains why the variable could not be resolved, when applicable.
	Reason string `json:"reason,omitempty"`
	// Foreach lists the foreach iterations the variable was expanded for, outer
	// scope first. Empty for variables outside of any foreach.
	Foreach []ElementBinding `json:"foreach,omitempty"`
}

// ContextEntryDiagnostic is the load result of a rule-level context entry.
type ContextEntryDiagnostic struct {
	// Name is the context entry name (the variable root it exposes).
	Name string `json:"name"`
	// Kind is the entry kind: ConfigMap, APICall, Variable, GlobalReference or
	// ImageRegistry.
	Kind string `json:"kind"`
	// Status is the load outcome.
	Status ResolutionStatus `json:"status"`
	// ValueType is the JSON type of the loaded entry.
	ValueType string `json:"valueType,omitempty"`
	// Value is the loaded entry content.
	Value interface{} `json:"value,omitempty"`
	// Reason explains why the entry could not be loaded, when applicable.
	Reason string `json:"reason,omitempty"`
}

// RuleDiagnostic aggregates diagnostics for one rule.
type RuleDiagnostic struct {
	// Name is the rule name.
	Name string `json:"name"`
	// RuleType is validation, mutation, generation or imageVerification.
	RuleType string `json:"ruleType"`
	// ContextEntries are the load results of the rule's context entries.
	ContextEntries []ContextEntryDiagnostic `json:"contextEntries,omitempty"`
	// Variables contains one diagnostic per variable occurrence and foreach
	// expansion.
	Variables []VariableDiagnostic `json:"variables,omitempty"`
	// Errors contains rule-level diagnostics that are not attached to a single
	// variable, for example a foreach-scoped context entry that failed to load.
	Errors []string `json:"errors,omitempty"`
}

// ResourceReference references the resource the diagnostics were computed for.
type ResourceReference struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
}

// Report is the variable expansion diagnostic of one policy/resource pair.
type Report struct {
	// PolicyName is the policy name.
	PolicyName string `json:"policyName"`
	// PolicyNamespace is the policy namespace (empty for ClusterPolicies).
	PolicyNamespace string `json:"policyNamespace,omitempty"`
	// PolicyKind is ClusterPolicy or Policy.
	PolicyKind string `json:"policyKind"`
	// PolicyRevision is the policy resourceVersion the diagnostics were computed
	// against.
	PolicyRevision string `json:"policyRevision"`
	// Resource is the resource the diagnostics were computed for.
	Resource ResourceReference `json:"resource"`
	// Operation is the admission operation used while building the context.
	Operation string `json:"operation"`
	// Rules contains one RuleDiagnostic per policy rule.
	Rules []RuleDiagnostic `json:"rules"`
}

// Config holds the dependencies required to build variable diagnostics.
type Config struct {
	// JP is the JMESPath processor used to evaluate expressions.
	JP jmespath.Interface
	// Configuration provides engine configuration (context size limits, ...).
	Configuration config.Configuration
	// Client is used by APICall context entries. It may be nil when API calls are
	// not available.
	Client engineapi.RawClient
	// RegistryClientFactory is used by ImageRegistry context entries.
	RegistryClientFactory engineapi.RegistryClientFactory
	// ContextLoader builds the loader used to resolve context entries. Pass
	// factories.DefaultContextLoaderFactory to reuse the engine defaults.
	ContextLoader engineapi.ContextLoaderFactory
}

// Option customizes a Diagnose run.
type Option func(*options)

type options struct {
	operation     kyvernov1.AdmissionOperation
	admissionInfo *kyvernov2.RequestInfo
}

// WithOperation sets the admission operation used to build the policy context
// (defaults to CREATE).
func WithOperation(operation kyvernov1.AdmissionOperation) Option {
	return func(o *options) {
		o.operation = operation
	}
}

// WithAdmissionInfo provides admission request information (user info, roles, ...).
func WithAdmissionInfo(admissionInfo kyvernov2.RequestInfo) Option {
	return func(o *options) {
		o.admissionInfo = &admissionInfo
	}
}

// Diagnostic expands policy variables without executing mutate/generate rule logic.
type Diagnostic struct {
	jp             jmespath.Interface
	configuration  config.Configuration
	client         engineapi.RawClient
	rclientFactory engineapi.RegistryClientFactory
	contextLoader  engineapi.ContextLoaderFactory
	log            logr.Logger
}

// New creates a Diagnostic from the given configuration.
func New(cfg Config) *Diagnostic {
	configuration := cfg.Configuration
	if configuration == nil {
		configuration = config.NewDefaultConfiguration(false)
	}
	jp := cfg.JP
	if jp == nil {
		jp = jmespath.New(configuration)
	}
	return &Diagnostic{
		jp:             jp,
		configuration:  configuration,
		client:         cfg.Client,
		rclientFactory: cfg.RegistryClientFactory,
		contextLoader:  cfg.ContextLoader,
		log:            logging.WithName("variables-diagnostic"),
	}
}

// Diagnose computes the variable expansion report of a policy against a resource. It
// does not mutate the resource nor run generate rules, and it evaluates every rule in
// its own isolated policy context.
func (d *Diagnostic) Diagnose(
	ctx context.Context,
	policy kyvernov1.PolicyInterface,
	resource unstructured.Unstructured,
	opts ...Option,
) (*Report, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is required")
	}
	o := &options{operation: kyvernov1.Create}
	for _, opt := range opts {
		opt(o)
	}
	rules := policy.GetSpec().Rules
	report := &Report{
		PolicyName:      policy.GetName(),
		PolicyNamespace: policy.GetNamespace(),
		PolicyKind:      policy.GetKind(),
		PolicyRevision:  policy.GetResourceVersion(),
		Resource: ResourceReference{
			APIVersion: resource.GetAPIVersion(),
			Kind:       resource.GetKind(),
			Namespace:  resource.GetNamespace(),
			Name:       resource.GetName(),
		},
		Operation: string(o.operation),
		Rules:     make([]RuleDiagnostic, 0, len(rules)),
	}
	for i := range rules {
		rule := rules[i]
		ruleDiagnostic, err := d.diagnoseRule(ctx, policy, resource, rule, o)
		if err != nil {
			return nil, fmt.Errorf("failed to diagnose rule %s: %w", rule.Name, err)
		}
		report.Rules = append(report.Rules, ruleDiagnostic)
	}
	return report, nil
}

func (d *Diagnostic) diagnoseRule(
	ctx context.Context,
	policy kyvernov1.PolicyInterface,
	resource unstructured.Unstructured,
	rule kyvernov1.Rule,
	o *options,
) (RuleDiagnostic, error) {
	// A fresh policy context per rule guarantees rule-level isolation: context
	// entries, image info and foreach element bindings computed for this rule cannot
	// be observed by another rule evaluated for the same resource.
	policyContext, err := policycontext.NewPolicyContext(d.jp, resource, o.operation, o.admissionInfo, d.configuration)
	if err != nil {
		return RuleDiagnostic{}, err
	}
	policyContext = policyContext.WithPolicy(policy)
	jsonCtx := policyContext.JSONContext()
	result := RuleDiagnostic{
		Name:           rule.Name,
		RuleType:       ruleType(rule),
		ContextEntries: []ContextEntryDiagnostic{},
		Variables:      []VariableDiagnostic{},
	}
	// Load rule-level context entries one by one so a failure on one entry does not
	// hide the status of the others.
	var loader engineapi.ContextLoader
	if d.contextLoader != nil {
		loader = d.contextLoader(policy, rule)
	}
	// entryFailures records non-resolved context entries by name. A variable
	// referencing a failed entry would otherwise be reported as not-found (the
	// deferred loader is not retried after its first failure), so the entry's
	// status and reason are surfaced on the variable instead.
	entryFailures := map[string]ContextEntryDiagnostic{}
	for _, entry := range rule.Context {
		entryDiagnostic := d.loadContextEntry(ctx, loader, jsonCtx, entry)
		result.ContextEntries = append(result.ContextEntries, entryDiagnostic)
		if entryDiagnostic.Status != StatusResolved {
			entryFailures[entry.Name] = entryDiagnostic
		}
	}
	// Turn the rule into untyped JSON and collect every variable occurrence along
	// with the foreach scopes it belongs to.
	untypedRule, err := jsonutils.DocumentToUntyped(rule)
	if err != nil {
		return RuleDiagnostic{}, err
	}
	ruleMap, ok := untypedRule.(map[string]interface{})
	if !ok {
		return RuleDiagnostic{}, fmt.Errorf("unexpected rule document type %T", untypedRule)
	}
	extraction := extractVariables(ruleMap)
	// Resolve variables declared outside any foreach.
	for _, occ := range extraction.occurrences {
		if len(occ.scopes) > 0 {
			continue
		}
		for _, tok := range occ.tokens {
			result.Variables = append(result.Variables, d.resolveOccurrence(jsonCtx, occ, tok, nil, extraction.entryNames, entryFailures))
		}
	}
	// Expand foreach scopes. Nested foreach arrays bind element/element0/... exactly
	// like the engine does, and each scope is checkpointed/restored so bindings do
	// not leak.
	for _, root := range extraction.roots {
		d.bindScope(ctx, loader, policyContext, jsonCtx, root, nil, nil, extraction, entryFailures, &result)
	}
	sort.SliceStable(result.Variables, func(i, j int) bool {
		if result.Variables[i].Location == result.Variables[j].Location {
			return result.Variables[i].Expression < result.Variables[j].Expression
		}
		return result.Variables[i].Location < result.Variables[j].Location
	})
	return result, nil
}

func (d *Diagnostic) bindScope(
	ctx context.Context,
	loader engineapi.ContextLoader,
	policyContext engineapi.PolicyContext,
	jsonCtx enginecontext.Interface,
	sc *scope,
	bindings []ElementBinding,
	chains []*scope,
	extraction *extraction,
	entryFailures map[string]ContextEntryDiagnostic,
	result *RuleDiagnostic,
) {
	chain := append(append([]*scope{}, chains...), sc)
	jsonCtx.Checkpoint()
	defer jsonCtx.Restore()
	elements, err := engineutils.EvaluateList(sc.list, jsonCtx)
	if err != nil {
		// The list cannot be evaluated: every occurrence under this scope (or a
		// nested one) is reported as unbound, with the list error as the reason.
		for _, occ := range extraction.occurrences {
			if !scopeChainMatches(occ.scopes, chain) {
				continue
			}
			for _, tok := range occ.tokens {
				diag := d.resolveOccurrence(jsonCtx, occ, tok, bindings, extraction.entryNames, entryFailures)
				diag.Status = StatusElementNotBound
				diag.Conversion = ConversionNone
				diag.Value = nil
				diag.ValueType = ""
				diag.Reason = fmt.Sprintf("foreach list %q could not be evaluated: %v", sc.list, err)
				result.Variables = append(result.Variables, diag)
			}
		}
		return
	}
	for index, element := range elements {
		if element == nil {
			continue
		}
		// Reset (but keep the checkpoint) before binding each element, mirroring the
		// engine foreach loop.
		jsonCtx.Reset()
		elementScopeFalse := false
		currentBindings := append(append([]ElementBinding{}, bindings...), ElementBinding{List: sc.list, Index: index})
		if err := engineutils.AddElementToContext(policyContext, element, index, sc.depth, &elementScopeFalse); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to bind element: %v", bindingPath(currentBindings), err))
			continue
		}
		// foreach scopes may declare their own context entries. Load them per
		// element. Failures are both recorded as rule-level errors and associated
		// with the entry name so variables referencing them report the real cause.
		if scopeEntries, convErr := contextEntriesFromRaw(sc.raw["context"]); convErr == nil {
			for _, entry := range scopeEntries {
				entryDiagnostic := d.loadContextEntry(ctx, loader, jsonCtx, entry)
				if entryDiagnostic.Status != StatusResolved {
					entryFailures[entry.Name] = entryDiagnostic
					result.Errors = append(result.Errors, fmt.Sprintf("%s: context entry %q failed to load (%s): %s",
						bindingPath(currentBindings), entry.Name, entryDiagnostic.Status, entryDiagnostic.Reason))
				}
			}
		}
		for _, occ := range extraction.occurrences {
			if !sameScopeChain(occ.scopes, chain) {
				continue
			}
			for _, tok := range occ.tokens {
				result.Variables = append(result.Variables, d.resolveOccurrence(jsonCtx, occ, tok, currentBindings, extraction.entryNames, entryFailures))
			}
		}
		// Recurse into nested foreach arrays with the element still bound.
		for _, child := range sc.children {
			d.bindScope(ctx, loader, policyContext, jsonCtx, child, currentBindings, chain, extraction, entryFailures, result)
		}
	}
}

func scopeChainMatches(occurrenceChain, prefix []*scope) bool {
	if len(occurrenceChain) < len(prefix) {
		return false
	}
	for i := range prefix {
		if occurrenceChain[i] != prefix[i] {
			return false
		}
	}
	return true
}

func sameScopeChain(occurrenceChain, chain []*scope) bool {
	if len(occurrenceChain) != len(chain) {
		return false
	}
	return scopeChainMatches(occurrenceChain, chain)
}

func bindingPath(bindings []ElementBinding) string {
	parts := make([]string, 0, len(bindings))
	for _, b := range bindings {
		parts = append(parts, fmt.Sprintf("foreach[%s][%d]", b.List, b.Index))
	}
	return strings.Join(parts, ".")
}

func (d *Diagnostic) loadContextEntry(
	ctx context.Context,
	loader engineapi.ContextLoader,
	jsonCtx enginecontext.Interface,
	entry kyvernov1.ContextEntry,
) ContextEntryDiagnostic {
	diag := ContextEntryDiagnostic{Name: entry.Name, Kind: contextEntryKind(entry)}
	if loader == nil {
		diag.Status = StatusDisabled
		diag.Reason = "no context loader configured; context entries cannot be resolved"
		return diag
	}
	// Entries are registered as deferred loaders, but invoking Load with a single
	// entry also covers the eager-loading path. Querying the entry name afterwards
	// forces the deferred loader to run, so fetch errors are reported here.
	if err := loader.Load(ctx, d.jp, d.client, d.rclientFactory, []kyvernov1.ContextEntry{entry}, jsonCtx); err != nil {
		diag.Status, diag.Reason = classifyError(err)
		d.log.V(4).Info("context entry failed to load", "entry", entry.Name, "kind", diag.Kind, "status", diag.Status, "reason", diag.Reason)
		return diag
	}
	value, err := jsonCtx.Query(entry.Name)
	if err != nil {
		diag.Status, diag.Reason = classifyError(err)
		d.log.V(4).Info("context entry failed to load", "entry", entry.Name, "kind", diag.Kind, "status", diag.Status, "reason", diag.Reason)
		return diag
	}
	diag.Status = StatusResolved
	diag.Value = value
	diag.ValueType = jsonTypeName(value)
	return diag
}

func (d *Diagnostic) resolveOccurrence(
	eval enginecontext.EvalInterface,
	occ occurrence,
	tok token,
	bindings []ElementBinding,
	entryNames map[string]struct{},
	entryFailures map[string]ContextEntryDiagnostic,
) VariableDiagnostic {
	diag := VariableDiagnostic{
		Expression: tok.expr,
		Location:   occ.pointer,
		Shallow:    tok.shallow,
		Conversion: ConversionNone,
		Foreach:    append([]ElementBinding{}, bindings...),
	}
	expr := tok.expr
	// The @ self-reference symbol resolves to target when available and falls back
	// to request.object. Its concrete path is derived from the rule pointer, exactly
	// like the engine substitution does.
	if expr == "@" {
		expr = resolveSelfReference(eval, occ.pointer)
		diag.Expression = expr
	}
	// DELETE requests silently rewrite request.object into request.oldObject.
	if eval.QueryOperation() == string(kyvernov1.Delete) {
		expr = strings.ReplaceAll(expr, "request.object", "request.oldObject")
		diag.Expression = expr
	}
	source, contextEntry := classifySource(expr, entryNames)
	diag.Source = source
	diag.ContextEntry = contextEntry
	value, err := eval.Query(expr)
	if err != nil {
		diag.Status, diag.Reason = classifyError(err)
		// A failed entry is only fetched once (deferred loaders do not retry), so a
		// variable referencing it normally surfaces as not-found. Report the entry
		// failure instead, which carries the actionable cause (permission denied,
		// load error, disabled source, ...).
		if contextEntry != "" {
			if failed, ok := entryFailures[contextEntry]; ok && failed.Status != StatusResolved {
				diag.Status = failed.Status
				diag.Reason = fmt.Sprintf("context entry %q failed to load (%s): %s", contextEntry, failed.Status, failed.Reason)
			}
		}
		return diag
	}
	diag.Status = StatusResolved
	diag.Value = value
	diag.ValueType = jsonTypeName(value)
	switch {
	case tok.whole:
		diag.Conversion = ConversionNative
	case value == nil:
		diag.Conversion = ConversionJSON
	case isString(value):
		diag.Conversion = ConversionString
	default:
		diag.Conversion = ConversionJSON
	}
	return diag
}

func classifyError(err error) (ResolutionStatus, string) {
	var notFound gojmespath.NotFoundError
	if errors.As(err, &notFound) {
		return StatusNotFound, fmt.Sprintf("JMESPath path not found: %v", err)
	}
	var invalid enginecontext.InvalidVariableError
	if errors.As(err, &invalid) {
		return StatusInvalidExpression, err.Error()
	}
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || strings.Contains(err.Error(), "permission denied") {
		return StatusPermissionDenied, err.Error()
	}
	message := err.Error()
	if strings.Contains(message, "incorrect query") || strings.Contains(message, "invalid JMESPath") {
		return StatusInvalidExpression, message
	}
	return StatusQueryError, message
}

// resolveSelfReference converts the @ symbol into a concrete JMESPath path using the
// rule pointer: it skips the foreach scopes and the two rule-specific pointer
// segments (e.g. mutate / overlay or validate / pattern), then prefixes the result
// with target (when available) or request.object.
func resolveSelfReference(eval enginecontext.EvalInterface, pointer string) string {
	pathPrefix := "target"
	if _, err := eval.Query("target"); err != nil {
		pathPrefix = "request.object"
	}
	segments := jsonpointer.ParsePath(pointer).SkipPast("foreach").SkipN(2).Prepend(strings.Split(pathPrefix, ".")...)
	return segments.JMESPath()
}

func contextEntryKind(entry kyvernov1.ContextEntry) string {
	switch {
	case entry.ConfigMap != nil:
		return "ConfigMap"
	case entry.APICall != nil:
		return "APICall"
	case entry.GlobalReference != nil:
		return "GlobalReference"
	case entry.ImageRegistry != nil:
		return "ImageRegistry"
	case entry.Variable != nil:
		return "Variable"
	default:
		return "Unknown"
	}
}

func ruleType(rule kyvernov1.Rule) string {
	switch {
	case rule.HasVerifyImages():
		return "imageVerification"
	case rule.HasValidate():
		return "validation"
	case rule.HasMutate():
		return "mutation"
	case rule.HasGenerate():
		return "generation"
	default:
		return "unknown"
	}
}

func jsonTypeName(value interface{}) string {
	switch value.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case int, int32, int64, float32, float64, json.Number:
		return "number"
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "array"
	default:
		return fmt.Sprintf("%T", value)
	}
}

func isString(value interface{}) bool {
	_, ok := value.(string)
	return ok
}
