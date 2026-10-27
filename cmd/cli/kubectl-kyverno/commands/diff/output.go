package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

const absentResult = "-"

// visibleReport returns the report filtered according to the output mode.
func visibleReport(report *Report, showUnchanged bool) *Report {
	if showUnchanged {
		return report
	}
	filtered := &Report{Summary: report.Summary}
	for _, entry := range report.Results {
		if entry.Change != ChangeUnchanged {
			filtered.Results = append(filtered.Results, entry)
		}
	}
	return filtered
}

func render(out io.Writer, report *Report, format string, showUnchanged bool) error {
	switch format {
	case "json":
		return renderJSON(out, visibleReport(report, showUnchanged))
	case "table", "":
		return renderTable(out, visibleReport(report, showUnchanged))
	default:
		return fmt.Errorf("unsupported output format %q, supported formats are table and json", format)
	}
}

func renderJSON(out io.Writer, report *Report) error {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, string(encoded)); err != nil {
		return err
	}
	return nil
}

func renderTable(out io.Writer, report *Report) error {
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer,
		"POLICY KIND\tPOLICY NAMESPACE\tPOLICY\tRULE\tAPI GROUP\tRESOURCE KIND\tRESOURCE NAMESPACE\tRESOURCE\tOLD RESULT\tNEW RESULT\tCHANGE\tMESSAGE",
	)
	resultOrDash := func(result *string) string {
		if result == nil {
			return absentResult
		}
		return *result
	}
	for _, entry := range report.Results {
		// Engine messages may span several lines; keep each entry on one table row.
		message := strings.NewReplacer("\n", " ", "\t", " ").Replace(entry.Message)
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			entry.Policy.Kind,
			entry.Policy.Namespace,
			entry.Policy.Name,
			entry.Rule,
			entry.Resource.APIGroup,
			entry.Resource.Kind,
			entry.Resource.Namespace,
			entry.Resource.Name,
			resultOrDash(entry.OldResult),
			resultOrDash(entry.NewResult),
			string(entry.Change),
			message,
		)
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nSummary: %d added, %d removed, %d changed, %d unchanged, %d new failure(s)\n",
		report.Summary.Added,
		report.Summary.Removed,
		report.Summary.Changed,
		report.Summary.Unchanged,
		report.Summary.NewFailures,
	)
	return nil
}
