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
	fmt.Printf("\nDetected %s vulnerabilities\n\n", config.Yellow(len(r.Vulns)))

	table := tablewriter.NewWriter(os.Stdout)

	table.SetHeader([]string{"ID", "Name", "Current Version", "CVEID", "Score", "Level", "Description"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{1})

	for i, c := range r.Vulns {
		scroe := fmt.Sprintf("%.1f", c.Score)

		// Limit the length of description
		if len(c.Desc) > 200 {
			c.Desc = c.Desc[:200] + " ..."
		}

		vulnData := []string{
			strconv.Itoa(i + 1), c.Name, c.CorrectVersion, c.CVEID,
			scroe, judgeSeverity(c.Level), c.Desc,
		}

		table.Append(vulnData)
	}

	table.Render()

	return nil
}

// ResolveDockerData print the result of analyze by docker
func ResolveDockerData(ctx context.Context, r analyzer.Scanner) error {
	fmt.Printf("\nDetected %s vulnerabilities\n\n", config.Yellow(len(r.VulnContainers)))

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Container Detail", "Param",
		"Value", "Severity", "Description"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0, 1})

	for i, c := range r.VulnContainers {

		for _, v := range c.Threats {
			vulnData := []string{strconv.Itoa(i + 1),
				fmt.Sprintf("Name: %s\n ID: %s", c.ContainerName, c.ContainerID),
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
	fmt.Printf("\nDetected %s vulnerabilities\n\n", config.Yellow(len(r.VulnContainers)+len(r.VulnConfigures)))

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
		//
		//fmt.Printf("| %d | Pod Name: %s |  Namepsace: %s |\n", i+1, p.ContaineName, p.Namepsace)
		//fmt.Printf("-----------------------------\n")
		for _, v := range p.Threats {
			vulnData := []string{
				strconv.Itoa(i + 1), fmt.Sprintf("Name: %s \nNamespace: %s", p.ContainerName, p.Namepsace),
				v.Param, v.Value, v.Type,
				judgeSeverity(v.Severity), v.Describe,
			}

			table.Append(vulnData)
		}
	}
	table.Render()

	fmt.Printf("\nConfigures:\n")
	table = tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Typel", "Param", "Value",
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
		return config.Green(("low"))
	default:
		// ignore
	}
	return ""
}
