package analyzer

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Scanner struct {
	VulnContainers []*container

	EngineVersion string
	ServerVersion string
}

type container struct {
	ContainerID   string
	ContainerName string
	Status        string
	NodeName      string
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
	KConfig *rest.Config
	Version string

	VulnConfigures []*threat
	VulnContainers []*container
}
