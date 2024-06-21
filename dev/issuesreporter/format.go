package issuesreporter

import (
	"strings"
)

const defaultMaxLengthMessages = 1000

type ResultsFormatter struct {
	result PackageError
}

func (r ResultsFormatter) Title() string {
	return r.result.String()
}

func (r ResultsFormatter) Owners() []string {
	return r.result.Teams
}

func (r ResultsFormatter) Description() string {
	var sb strings.Builder
	if r.result.StackVersion != "" {
		sb.WriteString("- Stack version: `")
		sb.WriteString(r.result.StackVersion)
		sb.WriteString("`\n")
	}
	if r.result.Serverless {
		sb.WriteString("- Serverless run\n")
	}
	sb.WriteString("- Package: `")
	sb.WriteString(r.result.PackageName)
	sb.WriteString("`\n")
	sb.WriteString("- Failing test: `")
	sb.WriteString(r.result.Name)
	sb.WriteString("`\n")

	if r.result.DataStream != "" {
		sb.WriteString("- DataStream: `")
		sb.WriteString(r.result.DataStream)
		sb.WriteString("`\n")
	}
	sb.WriteString("\n")
	if r.result.Failure != "" {
		sb.WriteString("Failure:\n")
		sb.WriteString("```\n")
		sb.WriteString(truncateText(r.result.Failure, defaultMaxLengthMessages))
		sb.WriteString("\n")
		sb.WriteString("```\n")
		sb.WriteString("\n")
	}
	if r.result.Error != "" {
		sb.WriteString("Error:\n")
		sb.WriteString("```\n")
		sb.WriteString(truncateText(r.result.Error, defaultMaxLengthMessages))
		sb.WriteString("\n")
		sb.WriteString("```\n")
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString("CI Builds: \n")
	sb.WriteString("- ")
	sb.WriteString(r.result.BuildURL)
	sb.WriteString("\n")

	return sb.String()
}

func truncateText(message string, maxLength int) string {
	if len(message) <= maxLength {
		return message
	}
	return message[:strings.LastIndexAny(message[:maxLength], " ,.;:-}")]
}
