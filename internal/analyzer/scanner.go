package analyzer

import (
	"github.com/kvesta/vesta/pkg/inspector"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Scanner struct {
	DApi           inspector.DockerApi
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
	KClient     *kubernetes.Clientset
	KConfig     *rest.Config
	Version     string
	MasterNodes map[string]*nodeInfo

	VulnConfigures []*threat
	VulnContainers []*container
}

type nodeInfo struct {
	Role       map[string]string
	IsMaster   bool
	InternalIP string
}
