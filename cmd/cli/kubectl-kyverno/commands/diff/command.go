package diff

import (
	"fmt"
	"io"

	kyvernov2 "github.com/kyverno/kyverno/api/kyverno/v2"
	"github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/command"
	"github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/userinfo"
	"github.com/spf13/cobra"
)

// Options holds the diff command configuration.
type Options struct {
	ResourcePaths []string
	ValuesFile    string
	Variables     []string
	UserInfoPath  string
	OutputFormat  string
	FailExitCode  int
	ShowUnchanged bool
}

// ExitCodeError is returned when --fail-exit-code is set and the new policy
// set adds failures (including a pass -> fail transition).
type ExitCodeError struct {
	ExitCodeVal int
	NewFailures int
}

func (e ExitCodeError) Error() string {
	return fmt.Sprintf("exit code %d: %d new failure(s) found", e.ExitCodeVal, e.NewFailures)
}

// ExitCode implements the custom process exit code consumed by the CLI entry point.
func (e ExitCodeError) ExitCode() int {
	return e.ExitCodeVal
}

func Command() *cobra.Command {
	options := &Options{}
	cmd := &cobra.Command{
		Use:          "diff <old-policies> <new-policies> -r <resources>",
		Short:        command.FormatDescription(true, websiteUrl, false, description...),
		Long:         command.FormatDescription(false, websiteUrl, false, description...),
		Example:      command.FormatExamples(examples...),
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], args[1], options)
		},
	}
	cmd.Flags().StringSliceVarP(&options.ResourcePaths, "resource", "r", nil, "Path to resource files or directories (can be repeated)")
	cmd.Flags().StringVarP(&options.ValuesFile, "values-file", "f", "", "File containing values for policy variables")
	cmd.Flags().StringSliceVarP(&options.Variables, "set", "s", nil, "Set policy variables (key=value, can be repeated)")
	cmd.Flags().StringVarP(&options.UserInfoPath, "userinfo", "u", "", "Admission info file including roles, cluster roles and subjects")
	cmd.Flags().StringVarP(&options.OutputFormat, "output", "o", "table", "Output format: table or json")
	cmd.Flags().IntVar(&options.FailExitCode, "fail-exit-code", 0, "Exit with the given code (1-125) when the new policies add failures or change a pass into a fail; 0 disables it")
	cmd.Flags().BoolVar(&options.ShowUnchanged, "show-unchanged", false, "Also report rules whose result is identical on both sides")
	return cmd
}

func validate(oldPath, newPath string, options *Options) error {
	if options.ValuesFile != "" && len(options.Variables) > 0 {
		return fmt.Errorf("pass the values either using --set or --values-file, not both")
	}
	if options.FailExitCode < 0 || options.FailExitCode > 125 {
		return fmt.Errorf("--fail-exit-code must be between 0 and 125, got %d", options.FailExitCode)
	}
	switch options.OutputFormat {
	case "table", "json":
	default:
		return fmt.Errorf("unsupported output format %q, supported formats are table and json", options.OutputFormat)
	}
	if err := validateLocalPaths(oldSide, []string{oldPath}); err != nil {
		return err
	}
	if err := validateLocalPaths(newSide, []string{newPath}); err != nil {
		return err
	}
	return nil
}

func run(out, errOut io.Writer, oldPath, newPath string, options *Options) error {
	if err := validate(oldPath, newPath, options); err != nil {
		return err
	}
	resources, err := loadResources(options.ResourcePaths)
	if err != nil {
		return err
	}
	var requestInfo *kyvernov2.RequestInfo
	if options.UserInfoPath != "" {
		info, err := userinfo.Load(nil, options.UserInfoPath, "")
		if err != nil {
			return fmt.Errorf("failed to load request info: %w", err)
		}
		requestInfo = &info.RequestInfo
	}
	// Each side builds its own variable snapshot from the same inputs and owns
	// its store and fake client, so evaluations cannot share mutable state.
	oldVars, err := newVariables(errOut, options.ValuesFile, options.Variables)
	if err != nil {
		return err
	}
	newVars, err := newVariables(errOut, options.ValuesFile, options.Variables)
	if err != nil {
		return err
	}
	oldPolicies, err := loadPolicies(oldSide, []string{oldPath}, errOut)
	if err != nil {
		return err
	}
	newPolicies, err := loadPolicies(newSide, []string{newPath}, errOut)
	if err != nil {
		return err
	}
	oldResults, err := evaluateSide(oldSide, oldPolicies, resources, oldVars, requestInfo)
	if err != nil {
		return err
	}
	newResults, err := evaluateSide(newSide, newPolicies, resources, newVars, requestInfo)
	if err != nil {
		return err
	}
	report := compare(oldResults, newResults)
	if err := render(out, report, options.OutputFormat, options.ShowUnchanged); err != nil {
		return err
	}
	// Evaluation errors always fail the command, regardless of --fail-exit-code.
	if hasEvaluationErrors(oldResults, newResults) {
		return fmt.Errorf("one or more validate rules failed to evaluate (see error results above)")
	}
	if options.FailExitCode != 0 && report.Summary.NewFailures > 0 {
		return ExitCodeError{
			ExitCodeVal: options.FailExitCode,
			NewFailures: report.Summary.NewFailures,
		}
	}
	return nil
}
