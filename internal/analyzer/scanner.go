package analyzer

import (
	"k8s.io/client-go/kubernetes"
)

type Scanner struct {
	VulnContainers []*container

	EngineVersion string
	ServerVersion string
}

type container struct {
	ContainerID   string
	ContainerName string

	// For kubernetes
	Namepsace string
	Threats   []*threat
}

type threat struct {
	Param string
	Value string
	Type  string

	Describe  string
	Severity  string
	Reference string
}

type KScanner struct {
	KClient *kubernetes.Clientset
	Version string

	VulnConfigures []*threat
	VulnContainers []*container
}
