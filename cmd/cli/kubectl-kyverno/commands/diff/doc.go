package diff

var websiteUrl = `https://kyverno.io/docs/kyverno-cli/#diff`

var description = []string{
	`Compare validate rule results of two policy sets against the same resources.`,
	``,
	`The diff command evaluates an old and a new set of Policy/ClusterPolicy manifests against`,
	`the same local resources and variables, then aligns the validate rule results by policy`,
	`(kind/namespace/name), rule name and resource (group/kind/namespace/name). It reports added`,
	`and removed rules (a rename shows up as a removal and an addition) and pass/fail/skip/error`,
	`transitions. A rule missing on one side is shown as absent, never as pass.`,
	``,
	`The command runs fully offline: it never contacts a cluster or registry and never modifies`,
	`input files. Invalid input and evaluation errors always make the command fail.`,
}

var examples = [][]string{
	{
		`# Compare two policy versions against the same resources`,
		`KYVERNO_EXPERIMENTAL=true kyverno diff old-policies/ new-policies/ -r resources/`,
	},
	{
		`# Machine readable output`,
		`KYVERNO_EXPERIMENTAL=true kyverno diff old.yaml new.yaml -r resources/ -o json`,
	},
	{
		`# Exit 2 when the new policies add failures or change a pass into a fail`,
		`KYVERNO_EXPERIMENTAL=true kyverno diff old/ new/ -r resources/ --fail-exit-code 2`,
	},
}
