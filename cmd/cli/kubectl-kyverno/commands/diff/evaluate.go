package diff

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	kyvernov2 "github.com/kyverno/kyverno/api/kyverno/v2"
	clitest "github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/commands/test"
	"github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/policy"
	"github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/processor"
	cliResource "github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/resource"
	"github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/source"
	"github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/store"
	"github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/variables"
	"github.com/kyverno/kyverno/pkg/autogen"
	"github.com/kyverno/kyverno/pkg/clients/dclient"
	"github.com/kyverno/kyverno/pkg/config"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	policyvalidation "github.com/kyverno/kyverno/pkg/validation/policy"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	oldSide = "old"
	newSide = "new"
)

// validateLocalPaths makes sure the command cannot silently reach out to a
// cluster, registry, OCI registry, git repository or HTTP server.
func validateLocalPaths(label string, paths []string) error {
	for _, path := range paths {
		switch {
		case path == "-" || source.IsStdin(path):
			return fmt.Errorf("%s policies: stdin is not supported, use local files or directories", label)
		case source.IsOCI(path):
			return fmt.Errorf("%s policies: OCI references are not supported in offline mode (%s)", label, path)
		case source.IsGit(path):
			return fmt.Errorf("%s policies: git references are not supported in offline mode (%s)", label, path)
		case source.IsHttp(path):
			return fmt.Errorf("%s policies: http(s) references are not supported in offline mode (%s)", label, path)
		}
		if _, err := os.Stat(filepath.Clean(path)); err != nil {
			return fmt.Errorf("%s policies: %w", label, err)
		}
	}
	return nil
}

// loadPolicies loads Policy/ClusterPolicy manifests, rejecting everything else
// along with load and validation errors. Evaluation copies drop verifyImages
// rules because this command only compares validate rules and image
// verification would require registry access.
func loadPolicies(label string, paths []string, warnings io.Writer) ([]kyvernov1.PolicyInterface, error) {
	// diff is a read-only pre-release comparison tool, so like fix/report it stays out
	// of apply's hard block on kyverno.io Policy/ClusterPolicy (#17485): the command's
	// purpose is precisely to compare two versions of those policies.
	loaderResults, err := policy.Load(nil, "", true, paths...)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s policies: %w", label, err)
	}
	for _, warning := range loaderResults.Warnings {
		fmt.Fprintf(warnings, "Warning: %s: %s\n", warning.Path, warning.Warning)
	}
	for _, loaderErr := range loaderResults.NonFatalErrors {
		return nil, fmt.Errorf("failed to load %s policies from %s: %s", label, loaderErr.Path, loaderErr.Error)
	}
	if otherKinds := unsupportedPolicyKinds(loaderResults); otherKinds != "" {
		return nil, fmt.Errorf("%s policies: only Policy and ClusterPolicy are supported, found: %s", label, otherKinds)
	}
	if len(loaderResults.Policies) == 0 {
		return nil, fmt.Errorf("%s policies: no Policy or ClusterPolicy found in %s", label, strings.Join(paths, ", "))
	}
	seen := map[string]struct{}{}
	policies := make([]kyvernov1.PolicyInterface, 0, len(loaderResults.Policies))
	for _, loaded := range loaderResults.Policies {
		identity := fmt.Sprintf("%s/%s/%s", loaded.GetKind(), loaded.GetNamespace(), loaded.GetName())
		if _, ok := seen[identity]; ok {
			return nil, fmt.Errorf("duplicate policy %s in %s policies", identity, label)
		}
		seen[identity] = struct{}{}
		serviceAccount := config.KyvernoUserName(config.KyvernoServiceAccountName())
		if _, err := policyvalidation.Validate(loaded, nil, nil, true, serviceAccount, serviceAccount); err != nil {
			return nil, fmt.Errorf("invalid %s policy %s: %w", label, identity, err)
		}
		policies = append(policies, withoutVerifyImages(loaded))
	}
	return policies, nil
}

func unsupportedPolicyKinds(results *policy.LoaderResults) string {
	var kinds []string
	add := func(kind string, count int) {
		if count > 0 {
			kinds = append(kinds, fmt.Sprintf("%s (%d)", kind, count))
		}
	}
	add("ValidatingAdmissionPolicy", len(results.VAPs))
	add("ValidatingAdmissionPolicyBinding", len(results.VAPBindings))
	add("MutatingAdmissionPolicy", len(results.MAPs))
	add("MutatingAdmissionPolicyBinding", len(results.MAPBindings))
	add("ValidatingPolicy", len(results.ValidatingPolicies))
	add("ImageValidatingPolicy", len(results.ImageValidatingPolicies))
	add("GeneratingPolicy", len(results.GeneratingPolicies))
	add("DeletingPolicy", len(results.DeletingPolicies))
	add("CleanupPolicy", len(results.CleanupPolicies))
	add("MutatingPolicy", len(results.MutatingPolicies))
	add("PolicyException", len(results.PolicyExceptions))
	if n := len(results.EnvoyPolicies) + len(results.HTTPPolicies); n > 0 {
		add("authorization policy", n)
	}
	if len(results.PolicyCelExceptions) > 0 {
		add("CEL PolicyException", len(results.PolicyCelExceptions))
	}
	return strings.Join(kinds, ", ")
}

// withoutVerifyImages returns a deep copy of the policy with verifyImages rules
// removed. validate, mutate and generate rules are kept untouched so autogen
// behavior stays identical to a real admission evaluation; only validate rules
// produce results under the validate-only engine entry point.
func withoutVerifyImages(p kyvernov1.PolicyInterface) kyvernov1.PolicyInterface {
	filter := func(rules []kyvernov1.Rule) []kyvernov1.Rule {
		out := make([]kyvernov1.Rule, 0, len(rules))
		for _, rule := range rules {
			if rule.HasVerifyImages() {
				continue
			}
			out = append(out, rule)
		}
		return out
	}
	switch pol := p.(type) {
	case *kyvernov1.Policy:
		cp := pol.DeepCopy()
		cp.Spec.Rules = filter(cp.Spec.Rules)
		return cp
	case *kyvernov1.ClusterPolicy:
		cp := pol.DeepCopy()
		cp.Spec.Rules = filter(cp.Spec.Rules)
		return cp
	default:
		return p
	}
}

// loadResources loads the shared resource snapshot. Both sides evaluate deep
// copies of these resources, so input files are never modified and there is no
// cross-side state.
func loadResources(paths []string) ([]*unstructured.Unstructured, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one resource path is required")
	}
	files := make([]string, 0)
	for _, path := range paths {
		if source.IsHttp(path) {
			return nil, fmt.Errorf("resources: http(s) references are not supported in offline mode (%s)", path)
		}
		if path == "-" || source.IsStdin(path) {
			return nil, fmt.Errorf("resources: stdin is not supported, use local files or directories")
		}
		resolved, err := expandResourcePath(path)
		if err != nil {
			return nil, err
		}
		files = append(files, resolved...)
	}
	var loaded []*unstructured.Unstructured
	for _, file := range files {
		data, err := cliResource.GetFileBytes(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read resource %s: %w", file, err)
		}
		resources, err := cliResource.GetUnstructuredResources(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse resource %s: %w", file, err)
		}
		loaded = append(loaded, resources...)
	}
	flat, err := cliResource.FlattenResources(loaded)
	if err != nil {
		return nil, fmt.Errorf("failed to flatten resources: %w", err)
	}
	flat = clitest.ProcessResources(flat)
	seen := map[string]struct{}{}
	for _, resource := range flat {
		gvk := resource.GroupVersionKind()
		if gvk.Version == "" || gvk.Kind == "" {
			return nil, fmt.Errorf(
				"resource %s/%s is missing TypeMeta (apiVersion=%q kind=%q)",
				resource.GetNamespace(), resource.GetName(), resource.GetAPIVersion(), gvk.Kind,
			)
		}
		identity := fmt.Sprintf("%s/%s/%s/%s", gvk.Group, gvk.Kind, resource.GetNamespace(), resource.GetName())
		if _, ok := seen[identity]; ok {
			return nil, fmt.Errorf("duplicate resource %s in the resource inputs", identity)
		}
		seen[identity] = struct{}{}
	}
	return flat, nil
}

func expandResourcePath(path string) ([]string, error) {
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{clean}, nil
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", clean, err)
	}
	var files []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		full := filepath.Join(clean, entry.Name())
		if entry.IsDir() {
			nested, err := expandResourcePath(full)
			if err != nil {
				return nil, err
			}
			files = append(files, nested...)
			continue
		}
		if ext := filepath.Ext(entry.Name()); ext == ".yaml" || ext == ".yml" {
			files = append(files, full)
		}
	}
	return files, nil
}

// newLocalClient builds a fake Kubernetes client backed by the loaded
// resources, mirroring kyverno apply's local mode: policy context API calls
// resolve against the provided resources only.
func newLocalClient(resources []*unstructured.Unstructured) (dclient.Interface, error) {
	gvrToListKind := make(map[schema.GroupVersionResource]string)
	gvrToGVK := make(map[schema.GroupVersionResource]schema.GroupVersionKind)
	var discoveryGVRs []schema.GroupVersionResource
	seen := make(map[schema.GroupVersionResource]bool)
	objects := make([]runtime.Object, 0, len(resources))
	for _, resource := range resources {
		objects = append(objects, resource.DeepCopy())
		gvk := resource.GroupVersionKind()
		gvr, _ := meta.UnsafeGuessKindToResource(gvk)
		if !seen[gvr] {
			seen[gvr] = true
			gvrToListKind[gvr] = gvk.Kind + "List"
			gvrToGVK[gvr] = gvk
			discoveryGVRs = append(discoveryGVRs, gvr)
		}
	}
	client, err := dclient.NewFakeClient(runtime.NewScheme(), gvrToListKind, objects...)
	if err != nil {
		return nil, fmt.Errorf("failed to create local resource client: %w", err)
	}
	discovery := dclient.NewFakeDiscoveryClient(discoveryGVRs)
	for gvr, gvk := range gvrToGVK {
		discovery.AddGVRToGVKMapping(gvr, gvk)
	}
	client.SetDiscovery(discovery)
	return client, nil
}

// evaluateSide evaluates the validate rules of one policy set against deep
// copies of the shared resources. Rules that exist in the (possibly
// autogenerated) rule set but produce no engine response are recorded as skip,
// while rules absent from the policy set are not recorded at all.
func evaluateSide(
	label string,
	policies []kyvernov1.PolicyInterface,
	resources []*unstructured.Unstructured,
	vars *variables.Variables,
	userInfo *kyvernov2.RequestInfo,
) (sideResults, error) {
	localClient, err := newLocalClient(resources)
	if err != nil {
		return nil, err
	}
	var policyStore store.Store
	policyStore.SetLocal(true)
	policyStore.AllowApiCall(true)
	vars.SetInStore(&policyStore)
	var counts processor.ResultCounts
	results := sideResults{}
	for _, original := range resources {
		proc := processor.PolicyProcessor{
			Store:                &policyStore,
			Policies:             policies,
			Resource:             *original.DeepCopy(),
			Variables:            vars,
			UserInfo:             userInfo,
			NamespaceSelectorMap: vars.NamespaceSelectors(),
			Rc:                   &counts,
			Cluster:              false,
			Client:               localClient,
			Subresources:         vars.Subresources(),
			Out:                  io.Discard,
			NamespaceCache:       map[string]*unstructured.Unstructured{},
		}
		responses, err := proc.ApplyValidatePoliciesOnResource()
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate %s policies on resource %s/%s: %w",
				label, original.GetKind(), original.GetName(), err)
		}
		for _, response := range responses {
			genericPolicy := response.Policy()
			keyPolicy := policyKey{
				kind:      genericPolicy.GetKind(),
				namespace: genericPolicy.GetNamespace(),
				name:      genericPolicy.GetName(),
			}
			keyResource := resourceKey{
				group:     response.Resource.GroupVersionKind().Group,
				kind:      response.Resource.GetKind(),
				namespace: response.Resource.GetNamespace(),
				name:      response.Resource.GetName(),
			}
			for _, rule := range response.PolicyResponse.Rules {
				if rule.RuleType() != engineapi.Validation {
					continue
				}
				results.record(
					ruleKey{policy: keyPolicy, rule: rule.Name(), resource: keyResource},
					&ruleResult{status: rule.Status(), message: rule.Message()},
				)
			}
		}
	}
	// Default every declared validate rule that produced no response to skip,
	// so a missing rule response is never confused with a pass.
	for _, policy := range policies {
		keyPolicy := policyKey{
			kind:      policy.GetKind(),
			namespace: policy.GetNamespace(),
			name:      policy.GetName(),
		}
		for _, resource := range resources {
			keyResource := resourceKey{
				group:     resource.GroupVersionKind().Group,
				kind:      resource.GetKind(),
				namespace: resource.GetNamespace(),
				name:      resource.GetName(),
			}
			for _, rule := range autogen.Default.ComputeRules(policy, resource.GetKind()) {
				if !rule.HasValidate() {
					continue
				}
				key := ruleKey{policy: keyPolicy, rule: rule.Name, resource: keyResource}
				if _, ok := results[key]; !ok {
					results[key] = &ruleResult{status: engineapi.RuleStatusSkip}
				}
			}
		}
	}
	return results, nil
}

// newVariables builds one independent variable snapshot per side from the same
// inputs, matching the requirement that both evaluations start from the same
// variable snapshot without sharing mutable state.
func newVariables(out io.Writer, valuesFile string, setVars []string) (*variables.Variables, error) {
	vars, err := variables.New(out, nil, "", valuesFile, nil, setVars...)
	if err != nil {
		return nil, err
	}
	if _, err := processor.NormalizeValuesOperation(vars.GlobalOperation()); err != nil {
		return nil, err
	}
	return vars, nil
}
