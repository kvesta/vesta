package report

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/internal/analyzer"
	"github.com/kvesta/vesta/internal/vulnscan"

	"github.com/olekukonko/tablewriter"
)

// ResolveAnalysisData print the result of image scan
func ResolveAnalysisData(ctx context.Context, r vulnscan.Scanner) error {

	critical, high, medium, low := 0, 0, 0, 0

	for _, c := range r.Vulns {
		switch strings.ToLower(c.Level) {
		case "critical":
			critical += 1
		case "high":
			high += 1
		case "medium":
			medium += 1
		case "low":
			low += 1
		default:
			// ignore
		}
	}

	fmt.Printf("\nDetected %s vulnerabilities | "+
		"Critical: %s High: %s Medium: %s Low: %s\n\n",
		config.Yellow(len(r.Vulns)),
		config.Red(critical),
		config.Pink(high),
		config.Yellow(medium),
		config.Green(low))

	table := tablewriter.NewWriter(os.Stdout)

	table.SetHeader([]string{"ID", "Name", "Current/Vulnerable Version", "CVEID", "Score", "Level", "Description"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{1})

	var Des string
	var currentType = "System"
	for i, c := range r.Vulns {

		if c.Type != currentType {
			table.Render()
			table.ClearRows()

			currentType = c.Type
			fmt.Printf("\n\n%s:\n", c.Type)
		}

		scroe := fmt.Sprintf("%.1f", c.Score)

		// Limit the length of description
		if len(c.Desc) > 200 {
			Des = c.Desc[:200] + " ..."
		} else {
			Des = c.Desc
		}

		vulnData := []string{
			strconv.Itoa(i + 1), c.Name,
			fmt.Sprintf("%s / %s", c.CurrentVersion, c.VulnerableVersion),
			c.CVEID, scroe, judgeSeverity(c.Level), Des,
		}

		table.Append(vulnData)
	}

	table.Render()

	return nil
}

// ResolveDockerData print the result of analyze by docker
func ResolveDockerData(ctx context.Context, r analyzer.Scanner) error {

	critical, high, medium, low := 0, 0, 0, 0

	for _, c := range r.VulnContainers {
		for _, v := range c.Threats {
			switch strings.ToLower(v.Severity) {
			case "critical":
				critical += 1
			case "high":
				high += 1
			case "medium":
				medium += 1
			case "low":
				low += 1
			default:
				// ignore
			}
		}

	}

	fmt.Printf("\nDetected %s vulnerabilities | "+
		"Critical: %s High: %s Medium: %s Low: %s\n\n",
		config.Yellow(len(r.VulnContainers)),
		config.Red(critical),
		config.Pink(high),
		config.Yellow(medium),
		config.Green(low))

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Container Detail", "Param",
		"Value", "Severity", "Description"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0, 1})

	for i, c := range r.VulnContainers {

		for _, v := range c.Threats {
			vulnData := []string{strconv.Itoa(i + 1),
				fmt.Sprintf("Name: %s \nID: %s", c.ContainerName, c.ContainerID),
				v.Param, v.Value, judgeSeverity(v.Severity), v.Describe,
			}

			table.Append(vulnData)
		}
	}

	table.Render()

	return nil
}

// ResolveKuberData print the result of analyze by kubernetes
func ResolveKuberData(ctx context.Context, r analyzer.KScanner) error {

	// Report pod condition

	critical, high, medium, low, warning := 0, 0, 0, 0, 0

	for _, c := range r.VulnContainers {
		for _, v := range c.Threats {
			switch strings.ToLower(v.Severity) {
			case "critical":
				critical += 1
			case "high":
				high += 1
			case "medium":
				medium += 1
			case "low":
				low += 1
			case "warning":
				warning += 1
			default:
				// ignore
			}
		}

	}

	fmt.Printf("\nDetected %s vulnerabilities | "+
		"Critical: %s High: %s Medium: %s Low: %s Warning: %d\n\n",
		config.Yellow(len(r.VulnContainers)+len(r.VulnConfigures)),
		config.Red(critical),
		config.Pink(high),
		config.Yellow(medium),
		config.Green(low),
		warning)

	if len(r.VulnContainers)+len(r.VulnConfigures) == 0 {
		return nil
	}

	fmt.Printf("Pods:\n")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Pod Detail", "Param", "Value",
		"Type", "Severity", "Description"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0, 1})

	for i, p := range r.VulnContainers {
		for _, v := range p.Threats {

			nodeName := ""
			if r.MasterNodes[p.NodeName] != nil && r.MasterNodes[p.NodeName].IsMaster {
				nodeName = fmt.Sprintf("%s (%s)",
					p.NodeName, config.Red("Master"))
			} else {
				nodeName = p.NodeName
			}

			vulnData := []string{
				strconv.Itoa(i + 1), fmt.Sprintf("Name: %s | "+
					"Namespace: %s | "+
					"Status: %s | "+
					"Node Name: %s", p.ContainerName, p.Namepsace,
					p.Status, nodeName),
				v.Param, v.Value, v.Type,
				judgeSeverity(v.Severity), v.Describe,
			}

			table.Append(vulnData)
		}
	}
	table.Render()

	fmt.Printf("\nConfigures:\n")
	table = tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Type", "Param", "Value",
		"Severity", "Description"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{1})

	for i, c := range r.VulnConfigures {
		vulnData := []string{strconv.Itoa(i + 1), c.Type, c.Param,
			c.Value, judgeSeverity(c.Severity), c.Describe}
		table.Append(vulnData)

	}

	table.Render()

	return nil
}

func judgeSeverity(severity string) string {

	severityLow := strings.ToLower(severity)

	switch severityLow {
	case "critical":
		return config.Red("critical")
	case "high":
		return config.Pink("high")
	case "medium":
		return config.Yellow("medium")
	case "low":
		return config.Green("low")
	case "warning":
		return "warning"
	default:
		// ignore
	}
	return "unknown"
}
