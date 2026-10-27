## kyverno diff

Compare validate rule results of two policy sets against the same resources.

### Synopsis

Compare validate rule results of two policy sets against the same resources.
  
  The diff command evaluates an old and a new set of Policy/ClusterPolicy manifests against
  the same local resources and variables, then aligns the validate rule results by policy
  (kind/namespace/name), rule name and resource (group/kind/namespace/name). It reports added
  and removed rules (a rename shows up as a removal and an addition) and pass/fail/skip/error
  transitions. A rule missing on one side is shown as absent, never as pass.
  
  The command runs fully offline: it never contacts a cluster or registry and never modifies
  input files. Invalid input and evaluation errors always make the command fail.

  For more information visit https://kyverno.io/docs/kyverno-cli/#diff

```
kyverno diff <old-policies> <new-policies> -r <resources> [flags]
```

### Examples

```
  # Compare two policy versions against the same resources
  KYVERNO_EXPERIMENTAL=true kyverno diff old-policies/ new-policies/ -r resources/

  # Machine readable output
  KYVERNO_EXPERIMENTAL=true kyverno diff old.yaml new.yaml -r resources/ -o json

  # Exit 2 when the new policies add failures or change a pass into a fail
  KYVERNO_EXPERIMENTAL=true kyverno diff old/ new/ -r resources/ --fail-exit-code 2
```

### Options

```
      --fail-exit-code int   Exit with the given code (1-125) when the new policies add failures or change a pass into a fail; 0 disables it
  -h, --help                 help for diff
  -o, --output string        Output format: table or json (default "table")
  -r, --resource strings     Path to resource files or directories (can be repeated)
  -s, --set strings          Set policy variables (key=value, can be repeated)
      --show-unchanged       Also report rules whose result is identical on both sides
  -u, --userinfo string      Admission info file including roles, cluster roles and subjects
  -f, --values-file string   File containing values for policy variables
```

### Options inherited from parent commands

```
      --add_dir_header                      If true, adds the file directory to the header of the log messages
      --alsologtostderr                     log to standard error as well as files (no effect when -logtostderr=true)
      --alsologtostderrthreshold severity   logs at or above this threshold go to stderr when -alsologtostderr=true (no effect when -logtostderr=true)
      --kubeconfig string                   Paths to a kubeconfig. Only required if out-of-cluster.
      --legacy_stderr_threshold_behavior    If true, stderrthreshold is ignored when logtostderr=true (legacy behavior). If false, stderrthreshold is honored even when logtostderr=true (default true)
      --log_backtrace_at traceLocation      when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                      If non-empty, write log files in this directory (no effect when -logtostderr=true)
      --log_file string                     If non-empty, use this log file (no effect when -logtostderr=true)
      --log_file_max_size uint              Defines the maximum size a log file can grow to (no effect when -logtostderr=true). Unit is megabytes. If the value is 0, the maximum file size is unlimited. (default 1800)
      --logtostderr                         log to standard error instead of files (default true)
      --one_output                          If true, only write logs to their native severity level (vs also writing to each lower severity level; no effect when -logtostderr=true)
      --skip_headers                        If true, avoid header prefixes in the log messages
      --skip_log_headers                    If true, avoid headers when opening log files (no effect when -logtostderr=true)
      --stderrthreshold severity            logs at or above this threshold go to stderr when writing to files and stderr (no effect when -logtostderr=true or -alsologtostderr=true unless -legacy_stderr_threshold_behavior=false) (default 2)
  -v, --v Level                             number for the log level verbosity
      --vmodule moduleSpec                  comma-separated list of pattern=N settings for file-filtered logging
```

### SEE ALSO

* [kyverno](kyverno.md)	 - Kubernetes Native Policy Management.

