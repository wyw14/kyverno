package diagnostic

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/config"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"github.com/kyverno/kyverno/pkg/engine/factories"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"gotest.tools/v3/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

const testPolicy = `
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: diag-test
  resourceVersion: "123456"
spec:
  rules:
    - name: cm-vars
      match:
        any:
          - resources:
              kinds:
                - Pod
      context:
        - name: dex
          configMap:
            name: dex-config
            namespace: default
      validate:
        message: "owner={{ dex.data.owner }} replicas={{ request.object.spec.replicas }} missing={{ request.object.spec.missing }} shallow={{- request.object.metadata.name }}"
        pattern:
          spec:
            replicas: "{{ request.object.spec.replicas }}"
    - name: nested-arrays
      match:
        any:
          - resources:
              kinds:
                - Pod
      context:
        - name: podlist
          apiCall:
            urlPath: /api/v1/namespaces/default/pods
            jmesPath: items
      mutate:
        foreach:
          - list: request.object.spec.containers
            patchStrategicMerge:
              metadata:
                annotations:
                  pod.example/first-pod: "{{ podlist[0].metadata.name }}"
              spec:
                containers:
                  - name: "{{ element.name }}"
                    firstPort: "{{ element.ports[0].containerPort }}"
            foreach:
              - list: element.ports
                patchStrategicMerge:
                  spec:
                    containers:
                      - name: "{{ element0.name }}"
                        ports:
                          - containerPort: "{{ element.containerPort }}"
                            protocol: "{{ element.protocol }}"
                            missing: "{{ element.notAField }}"
    - name: forbidden-api
      match:
        any:
          - resources:
              kinds:
                - Pod
      context:
        - name: secrets
          apiCall:
            urlPath: /api/v1/namespaces/default/secrets
      validate:
        message: "secrets={{ secrets.items }}"
        pattern:
          spec: {}
    - name: isolated-rule-one
      match:
        any:
          - resources:
              kinds:
                - Pod
      context:
        - name: replicaCount
          variable:
            value: "{{ request.object.spec.replicas }}"
      validate:
        message: "count={{ replicaCount }}"
        pattern:
          spec:
            replicas: "{{ replicaCount }}"
    - name: isolated-rule-two
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "owner={{ dex.data.owner }} count={{ replicaCount }}"
        pattern:
          spec: {}
`

const testResource = `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  replicas: 3
  containers:
    - name: app
      ports:
        - containerPort: 8080
          protocol: TCP
        - containerPort: 9090
          protocol: UDP
    - name: sidecar
      ports:
        - containerPort: 6060
          protocol: TCP
`

type fakeConfigMapResolver struct {
	configMap *corev1.ConfigMap
	err       error
}

func (r *fakeConfigMapResolver) Get(_ context.Context, _, _ string) (*corev1.ConfigMap, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.configMap, nil
}

type fakeRawClient struct{}

func (c *fakeRawClient) RawAbsPath(_ context.Context, path, _ string, _ io.Reader) ([]byte, error) {
	if strings.Contains(path, "secrets") {
		return nil, apierrors.NewForbidden(
			schema.GroupResource{Resource: "secrets"},
			"mysecret",
			fmt.Errorf("RBAC: access denied"),
		)
	}
	if strings.Contains(path, "pods") {
		return []byte(`{
			"items": [
				{"metadata": {"name": "p1"}, "spec": {"containers": [{"name": "c"}]}}
			]
		}`), nil
	}
	return []byte(`{}`), nil
}

func newTestDiagnostic(t *testing.T) *Diagnostic {
	t.Helper()
	cfg := config.NewDefaultConfiguration(false)
	cmResolver := &fakeConfigMapResolver{
		configMap: &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "dex-config", Namespace: "default"},
			Data:       map[string]string{"owner": "admin@example.com"},
		},
	}
	factory := factories.DefaultContextLoaderFactory(cmResolver)
	return New(Config{
		JP:            jmespath.New(cfg),
		Configuration: cfg,
		Client:        &fakeRawClient{},
		ContextLoader: factory,
	})
}

func loadPolicyAndResource(t *testing.T) (*kyvernov1.ClusterPolicy, unstructured.Unstructured) {
	t.Helper()
	policy := &kyvernov1.ClusterPolicy{}
	assert.NilError(t, yaml.Unmarshal([]byte(testPolicy), policy))
	resource := unstructured.Unstructured{}
	assert.NilError(t, yaml.Unmarshal([]byte(testResource), &resource))
	return policy, resource
}

func findRule(report *Report, name string) *RuleDiagnostic {
	for i := range report.Rules {
		if report.Rules[i].Name == name {
			return &report.Rules[i]
		}
	}
	return nil
}

func findEntries(rule *RuleDiagnostic, name string) []ContextEntryDiagnostic {
	var result []ContextEntryDiagnostic
	for _, entry := range rule.ContextEntries {
		if entry.Name == name {
			result = append(result, entry)
		}
	}
	return result
}

func findVariables(rule *RuleDiagnostic, expression string) []VariableDiagnostic {
	var result []VariableDiagnostic
	for _, variable := range rule.Variables {
		if variable.Expression == expression {
			result = append(result, variable)
		}
	}
	return result
}

func requireVariable(t *testing.T, rule *RuleDiagnostic, expression string, foreachDepth int) VariableDiagnostic {
	t.Helper()
	for _, variable := range rule.Variables {
		if variable.Expression == expression && len(variable.Foreach) == foreachDepth {
			return variable
		}
	}
	t.Fatalf("variable %q (foreach depth %d) not found in rule %q", expression, foreachDepth, rule.Name)
	return VariableDiagnostic{}
}

func Test_Diagnose_ReportMetadataAndRevision(t *testing.T) {
	d := newTestDiagnostic(t)
	policy, resource := loadPolicyAndResource(t)
	report, err := d.Diagnose(context.Background(), policy, resource)
	assert.NilError(t, err)
	assert.Equal(t, report.PolicyName, "diag-test")
	assert.Equal(t, report.PolicyKind, "ClusterPolicy")
	assert.Equal(t, report.PolicyRevision, "123456")
	assert.Equal(t, report.Resource.Kind, "Pod")
	assert.Equal(t, report.Resource.Name, "test-pod")
	assert.Equal(t, report.Resource.Namespace, "default")
	assert.Equal(t, len(report.Rules), len(policy.Spec.Rules))
	assert.Equal(t, report.Operation, string(kyvernov1.Create))
}

func Test_Diagnose_ConfigMapContextAndConversions(t *testing.T) {
	d := newTestDiagnostic(t)
	policy, resource := loadPolicyAndResource(t)
	report, err := d.Diagnose(context.Background(), policy, resource)
	assert.NilError(t, err)
	rule := findRule(report, "cm-vars")
	assert.Assert(t, rule != nil)
	assert.Equal(t, rule.RuleType, "validation")
	// the ConfigMap context entry is loaded and exposes its content.
	entries := findEntries(rule, "dex")
	assert.Equal(t, len(entries), 1)
	assert.Equal(t, entries[0].Kind, "ConfigMap")
	assert.Equal(t, entries[0].Status, StatusResolved)
	assert.Equal(t, entries[0].ValueType, "object")
	// the owner variable comes from the ConfigMap and is embedded as a string.
	owner := requireVariable(t, rule, "dex.data.owner", 0)
	assert.Equal(t, owner.Status, StatusResolved)
	assert.Equal(t, owner.Source, SourceContextEntry)
	assert.Equal(t, owner.ContextEntry, "dex")
	assert.Equal(t, owner.ValueType, "string")
	assert.Equal(t, owner.Value, "admin@example.com")
	assert.Equal(t, owner.Conversion, ConversionString)
	// replicas occurs twice: whole-string native number in the pattern and JSON
	// embedded number in the message.
	replicas := findVariables(rule, "request.object.spec.replicas")
	assert.Equal(t, len(replicas), 2)
	var native, embedded bool
	for _, variable := range replicas {
		assert.Equal(t, variable.Status, StatusResolved)
		assert.Equal(t, variable.Source, SourceResource)
		assert.Equal(t, variable.ValueType, "number")
		assert.Equal(t, variable.Value, int64(3))
		if variable.Conversion == ConversionNative {
			native = true
			assert.Assert(t, len(variable.Foreach) == 0)
		}
		if variable.Conversion == ConversionJSON {
			embedded = true
		}
	}
	assert.Assert(t, native, "expected a native whole-string replicas occurrence")
	assert.Assert(t, embedded, "expected a JSON-embedded replicas occurrence")
	// a missing path is reported with a not-found reason instead of failing the run.
	missing := requireVariable(t, rule, "request.object.spec.missing", 0)
	assert.Equal(t, missing.Status, StatusNotFound)
	assert.Assert(t, missing.Reason != "")
	assert.Equal(t, missing.Conversion, ConversionNone)
	// the shallow substitution marker is preserved.
	shallow := requireVariable(t, rule, "request.object.metadata.name", 0)
	assert.Equal(t, shallow.Status, StatusResolved)
	assert.Equal(t, shallow.Shallow, true)
	assert.Equal(t, shallow.Value, "test-pod")
}

func Test_Diagnose_ApiCallAndNestedArrays(t *testing.T) {
	d := newTestDiagnostic(t)
	policy, resource := loadPolicyAndResource(t)
	report, err := d.Diagnose(context.Background(), policy, resource)
	assert.NilError(t, err)
	rule := findRule(report, "nested-arrays")
	assert.Assert(t, rule != nil)
	assert.Equal(t, rule.RuleType, "mutation")
	// the APICall context entry is fetched through the raw client and projected with
	// its JMESPath expression.
	entries := findEntries(rule, "podlist")
	assert.Equal(t, len(entries), 1)
	assert.Equal(t, entries[0].Kind, "APICall")
	assert.Equal(t, entries[0].Status, StatusResolved)
	assert.Equal(t, entries[0].ValueType, "array")
	// a variable backed by the API call resolves against the projected payload.
	firstPod := requireVariable(t, rule, "podlist[0].metadata.name", 1)
	assert.Equal(t, firstPod.Status, StatusResolved)
	assert.Equal(t, firstPod.Source, SourceContextEntry)
	assert.Equal(t, firstPod.ContextEntry, "podlist")
	assert.Equal(t, firstPod.Value, "p1")
	// outer foreach: one expansion per container.
	names := findVariables(rule, "element.name")
	assert.Equal(t, len(names), 2)
	for i, variable := range names {
		assert.Equal(t, variable.Status, StatusResolved)
		assert.Equal(t, variable.Source, SourceForEachElement)
		assert.Equal(t, len(variable.Foreach), 1)
		assert.Equal(t, variable.Foreach[0].List, "request.object.spec.containers")
		assert.Equal(t, variable.Foreach[0].Index, i)
		assert.Equal(t, variable.Value, []string{"app", "sidecar"}[i])
	}
	// arrays nested in elements are indexable.
	firstPorts := findVariables(rule, "element.ports[0].containerPort")
	assert.Equal(t, len(firstPorts), 2)
	assert.Equal(t, firstPorts[0].Value, int64(8080))
	assert.Equal(t, firstPorts[1].Value, int64(6060))
	// nested foreach: element0 stays bound to the container while element is bound
	// to each port, producing 2 + 1 expansions.
	containerPorts := findVariables(rule, "element.containerPort")
	assert.Equal(t, len(containerPorts), 3)
	expectedPorts := []int64{8080, 9090, 6060}
	expectedContainers := []string{"app", "app", "sidecar"}
	for i, variable := range containerPorts {
		assert.Equal(t, variable.Status, StatusResolved)
		assert.Equal(t, len(variable.Foreach), 2)
		assert.Equal(t, variable.Foreach[0].List, "request.object.spec.containers")
		assert.Equal(t, variable.Foreach[1].List, "element.ports")
		assert.Equal(t, variable.Value, expectedPorts[i])
		outerName := requireVariableAt(t, rule, "element0.name", variable.Foreach)
		assert.Equal(t, outerName.Value, expectedContainers[i])
	}
	protocols := findVariables(rule, "element.protocol")
	assert.Equal(t, len(protocols), 3)
	assert.Equal(t, protocols[0].Value, "TCP")
	assert.Equal(t, protocols[1].Value, "UDP")
	assert.Equal(t, protocols[2].Value, "TCP")
	// a missing field inside a nested element is reported per expansion.
	missingInner := findVariables(rule, "element.notAField")
	assert.Equal(t, len(missingInner), 3)
	for _, variable := range missingInner {
		assert.Equal(t, variable.Status, StatusNotFound)
		assert.Equal(t, len(variable.Foreach), 2)
	}
	// foreach diagnostics never mutate the resource: no annotations were applied.
	assert.DeepEqual(t, resource.GetAnnotations(), map[string]string(nil))
}

func requireVariableAt(t *testing.T, rule *RuleDiagnostic, expression string, bindings []ElementBinding) VariableDiagnostic {
	t.Helper()
	for _, variable := range rule.Variables {
		if variable.Expression != expression || len(variable.Foreach) != len(bindings) {
			continue
		}
		match := true
		for i := range bindings {
			if variable.Foreach[i] != bindings[i] {
				match = false
				break
			}
		}
		if match {
			return variable
		}
	}
	t.Fatalf("variable %q at %v not found in rule %q", expression, bindings, rule.Name)
	return VariableDiagnostic{}
}

func Test_Diagnose_ApiCallPermissionDenied(t *testing.T) {
	d := newTestDiagnostic(t)
	policy, resource := loadPolicyAndResource(t)
	report, err := d.Diagnose(context.Background(), policy, resource)
	assert.NilError(t, err)
	rule := findRule(report, "forbidden-api")
	assert.Assert(t, rule != nil)
	entries := findEntries(rule, "secrets")
	assert.Equal(t, len(entries), 1)
	assert.Equal(t, entries[0].Status, StatusPermissionDenied)
	assert.Assert(t, strings.Contains(entries[0].Reason, "permission denied"), entries[0].Reason)
	// variables referencing the entry surface the same permission error with a
	// precise reason instead of a generic failure.
	variable := requireVariable(t, rule, "secrets.items", 0)
	assert.Equal(t, variable.Status, StatusPermissionDenied)
	assert.Equal(t, variable.Source, SourceContextEntry)
	assert.Assert(t, strings.Contains(variable.Reason, "permission denied"), variable.Reason)
}

func Test_Diagnose_ContextIsIsolatedBetweenRules(t *testing.T) {
	d := newTestDiagnostic(t)
	policy, resource := loadPolicyAndResource(t)
	report, err := d.Diagnose(context.Background(), policy, resource)
	assert.NilError(t, err)
	ruleOne := findRule(report, "isolated-rule-one")
	assert.Assert(t, ruleOne != nil)
	entries := findEntries(ruleOne, "replicaCount")
	assert.Equal(t, len(entries), 1)
	assert.Equal(t, entries[0].Kind, "Variable")
	assert.Equal(t, entries[0].Status, StatusResolved)
	replicaCount := requireVariable(t, ruleOne, "replicaCount", 0)
	assert.Equal(t, replicaCount.Status, StatusResolved)
	assert.Equal(t, replicaCount.Value, float64(3))
	// the second rule declares neither dex nor replicaCount: entries loaded for the
	// other rules against the same resource must not leak into its context.
	ruleTwo := findRule(report, "isolated-rule-two")
	assert.Assert(t, ruleTwo != nil)
	assert.Equal(t, len(ruleTwo.ContextEntries), 0)
	for _, expression := range []string{"dex.data.owner", "replicaCount"} {
		variable := requireVariable(t, ruleTwo, expression, 0)
		assert.Equal(t, variable.Status, StatusNotFound)
		assert.Equal(t, variable.Source, SourceUnknown)
	}
	// and the cm-vars rule context entry must not have leaked either: rule two has
	// no resolved context-entry variables.
	for _, variable := range ruleTwo.Variables {
		assert.Assert(t, variable.Source != SourceContextEntry)
	}
}

func Test_Diagnose_ForeachListErrorIsReported(t *testing.T) {
	d := newTestDiagnostic(t)
	policy := &kyvernov1.ClusterPolicy{}
	err := yaml.Unmarshal([]byte(`
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: bad-list
  resourceVersion: "7"
spec:
  rules:
    - name: bad-foreach
      match:
        any:
          - resources:
              kinds:
                - Pod
      mutate:
        foreach:
          - list: request.object.spec.missingContainers
            patchStrategicMerge:
              metadata:
                labels:
                  name: "{{ element.name }}"
`), policy)
	assert.NilError(t, err)
	resource := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "p"},
		"spec":       map[string]interface{}{},
	}}
	report, err := d.Diagnose(context.Background(), policy, resource)
	assert.NilError(t, err)
	rule := findRule(report, "bad-foreach")
	assert.Assert(t, rule != nil)
	// the list failed to evaluate, so no element was bound: the occurrence is
	// reported once as element-not-bound without foreach indices.
	vars := findVariables(rule, "element.name")
	assert.Equal(t, len(vars), 1)
	variable := vars[0]
	assert.Equal(t, variable.Status, StatusElementNotBound)
	assert.Equal(t, len(variable.Foreach), 0)
	assert.Assert(t, strings.Contains(variable.Reason, "missingContainers"), variable.Reason)
	assert.Equal(t, report.PolicyRevision, "7")
}

func Test_ClassifySource(t *testing.T) {
	entries := map[string]struct{}{"dex": {}}
	cases := []struct {
		expr        string
		source      VariableSource
		contextName string
	}{
		{"request.object.metadata.name", SourceResource, ""},
		{"request.oldObject.metadata.name", SourceResource, ""},
		{"request.namespace", SourceRequest, ""},
		{"request.userInfo.username", SourceRequest, ""},
		{"target.metadata.name", SourceTarget, ""},
		{"images.containers.app.name", SourceImages, ""},
		{"serviceAccountName", SourceServiceAccount, ""},
		{"element.name", SourceForEachElement, ""},
		{"element0.name", SourceForEachElement, ""},
		{"elementIndex1", SourceForEachElement, ""},
		{"dex.data.owner", SourceContextEntry, "dex"},
		{`"dex-config".data`, SourceUnknown, ""},
		{"length(request.object.spec.containers)", SourceFunction, ""},
		{"unknownVariable.foo", SourceUnknown, ""},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			source, name := classifySource(tc.expr, entries)
			assert.Equal(t, source, tc.source)
			assert.Equal(t, name, tc.contextName)
		})
	}
}

var (
	_ engineapi.ConfigmapResolver = (*fakeConfigMapResolver)(nil)
	_ engineapi.RawClient         = (*fakeRawClient)(nil)
)
