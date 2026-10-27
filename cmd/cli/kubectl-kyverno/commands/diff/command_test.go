package diff

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func executeCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := Command()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestDiffCommandJSON(t *testing.T) {
	stdout, _, err := executeCommand(t,
		"testdata/old/policy.yaml",
		"testdata/new/policy.yaml",
		"-r", "testdata/resources",
		"-o", "json",
	)
	require.NoError(t, err)
	var report Report
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	assert.Equal(t, Summary{Added: 10, Removed: 5, Changed: 1, Unchanged: 4, NewFailures: 4}, report.Summary)
	var flip *Entry
	for i := range report.Results {
		entry := &report.Results[i]
		if entry.Rule == "require-labels" && entry.Resource.Name == "pod-app" {
			flip = entry
		}
		if entry.Change == ChangeAdded {
			assert.Nil(t, entry.OldResult, "added rule %s must not be reported as a previous pass", entry.Rule)
			assert.NotNil(t, entry.NewResult)
		}
		if entry.Change == ChangeRemoved {
			assert.Nil(t, entry.NewResult, "removed rule %s must be reported as absent, not pass", entry.Rule)
			assert.NotNil(t, entry.OldResult)
		}
	}
	require.NotNil(t, flip, "expected a pass -> fail entry for require-labels/pod-app")
	assert.Equal(t, "pass", *flip.OldResult)
	assert.Equal(t, "fail", *flip.NewResult)
	// the renamed rule surfaces as a removal and an addition on the pod that violates it
	var removedRename, addedRename bool
	for _, entry := range report.Results {
		if entry.Rule == "disallow-latest" && entry.Resource.Name == "pod-latest" {
			assert.Equal(t, ChangeRemoved, entry.Change)
			assert.Equal(t, "fail", *entry.OldResult)
			removedRename = true
		}
		if entry.Rule == "disallow-latest-image" && entry.Resource.Name == "pod-latest" {
			assert.Equal(t, ChangeAdded, entry.Change)
			assert.Equal(t, "fail", *entry.NewResult)
			addedRename = true
		}
	}
	assert.True(t, removedRename && addedRename)
	// unchanged rows are hidden by default.
	for _, entry := range report.Results {
		assert.NotEqual(t, ChangeUnchanged, entry.Change)
	}
}

func TestDiffCommandShowUnchanged(t *testing.T) {
	stdout, _, err := executeCommand(t,
		"testdata/old/policy.yaml",
		"testdata/new/policy.yaml",
		"-r", "testdata/resources",
		"-o", "json",
		"--show-unchanged",
	)
	require.NoError(t, err)
	var report Report
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	// 4 rules in the union (renamed rule counts twice) x 5 resources.
	assert.Len(t, report.Results, 20)
}

func TestDiffCommandTable(t *testing.T) {
	stdout, _, err := executeCommand(t,
		"testdata/old/policy.yaml",
		"testdata/new/policy.yaml",
		"-r", "testdata/resources/resources.yaml",
	)
	require.NoError(t, err)
	assert.Contains(t, stdout, "POLICY KIND")
	assert.Contains(t, stdout, "OLD RESULT")
	assert.Contains(t, stdout, "NEW RESULT")
	assert.Contains(t, stdout, "Summary: 10 added, 5 removed, 1 changed, 4 unchanged, 4 new failure(s)")
	// absent results are rendered as "-" rather than "pass"
	assert.Contains(t, stdout, " - ", "expected a dash for a missing side, got %s", stdout)
}

func TestDiffCommandFailExitCode(t *testing.T) {
	_, _, err := executeCommand(t,
		"testdata/old/policy.yaml",
		"testdata/new/policy.yaml",
		"-r", "testdata/resources",
		"-o", "json",
		"--fail-exit-code", "2",
	)
	var exitErr ExitCodeError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 2, exitErr.ExitCode())
	assert.Equal(t, 4, exitErr.NewFailures)
}

func TestDiffCommandNoNewFailuresExitZero(t *testing.T) {
	// Comparing a policy set with itself yields only unchanged rows: no new failures.
	_, _, err := executeCommand(t,
		"testdata/old/policy.yaml",
		"testdata/old/policy.yaml",
		"-r", "testdata/resources",
		"-o", "json",
		"--fail-exit-code", "3",
	)
	assert.NoError(t, err)
}

func TestDiffCommandEvaluationErrorsFail(t *testing.T) {
	stdout, _, err := executeCommand(t,
		"testdata/eval-error/policy.yaml",
		"testdata/eval-error/policy.yaml",
		"-r", "testdata/resources",
		"-o", "json",
		"--show-unchanged",
		"--fail-exit-code", "2",
	)
	require.Error(t, err)
	// the report is still emitted before failing.
	var report Report
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	assert.NotEmpty(t, report.Results)
	assert.Equal(t, "eval-error-policy", report.Results[0].Policy.Name)
	errorCells := 0
	for _, entry := range report.Results {
		if entry.OldResult != nil && *entry.OldResult == "error" {
			errorCells++
		}
	}
	assert.Greater(t, errorCells, 0)
	_, isExitCodeError := err.(ExitCodeError)
	assert.False(t, isExitCodeError, "evaluation errors must exit 1, not the regression exit code")
}

func TestDiffCommandInvalidInputs(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing old policy path", []string{"testdata/does-not-exist", "testdata/new/policy.yaml", "-r", "testdata/resources"}},
		{"unsupported policy kind", []string{"testdata/unsupported", "testdata/new/policy.yaml", "-r", "testdata/resources"}},
		{"missing resources", []string{"testdata/old/policy.yaml", "testdata/new/policy.yaml", "-r", "testdata/no-resources"}},
		{"bad output format", []string{"testdata/old/policy.yaml", "testdata/new/policy.yaml", "-r", "testdata/resources", "-o", "yaml"}},
		{"values file and set", []string{"testdata/old/policy.yaml", "testdata/new/policy.yaml", "-r", "testdata/resources", "-f", "x", "-s", "a=b"}},
		{"invalid exit code", []string{"testdata/old/policy.yaml", "testdata/new/policy.yaml", "-r", "testdata/resources", "--fail-exit-code", "126"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := executeCommand(t, tc.args...)
			assert.Error(t, err)
		})
	}
}

func TestDiffCommandRejectsRemoteInputs(t *testing.T) {
	_, _, err := executeCommand(t,
		"https://example.com/old.yaml",
		"testdata/new/policy.yaml",
		"-r", "testdata/resources",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offline")
	_, _, err = executeCommand(t,
		"testdata/old/policy.yaml",
		"testdata/new/policy.yaml",
		"-r", "https://example.com/resources.yaml",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offline")
}

func TestDiffCommandWritesNothingBesideOutputs(t *testing.T) {
	// The command must not mutate resource files: snapshot a file, run, compare.
	path := filepath.Join("testdata", "resources", "resources.yaml")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	_, _, err = executeCommand(t,
		"testdata/old/policy.yaml",
		"testdata/new/policy.yaml",
		"-r", path,
		"-o", "json",
	)
	require.NoError(t, err)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}
