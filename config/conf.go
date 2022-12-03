package config

import (
	"context"

	"github.com/fatih/color"
)

var (
	Yellow = color.New(color.FgYellow).SprintFunc()
	Red    = color.New(color.FgRed).SprintFunc()
	Green  = color.New(color.FgGreen).SprintFunc()
	Pink   = color.New(color.FgMagenta).SprintFunc()

	Ctx = context.Background()
)
