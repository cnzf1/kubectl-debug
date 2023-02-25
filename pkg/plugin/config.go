package plugin

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct {
	DebuggerPort                int      `yaml:"debuggerPort,omitempty"`
	Image                       string   `yaml:"image,omitempty"`
	RegistrySecretName          string   `yaml:"registrySecretName,omitempty"`
	RegistrySecretNamespace     string   `yaml:"registrySecretNamespace,omitempty"`
	RegistrySkipTLSVerify       bool     `yaml:"registrySkipTLSVerify,omitempty"`
	ForkPodRetainLabels         []string `yaml:"forkPodRetainLabels,omitempty"`
	DebuggerDaemonSet           string   `yaml:"debuggerDaemonset,omitempty"`
	DebuggerNamespace           string   `yaml:"debuggerNamespace,omitempty"`
	Command                     []string `yaml:"command,omitempty"`
	PortForward                 bool     `yaml:"portForward,omitempty"`
	Debuggerless                bool     `yaml:"debuggerless,omitempty"`
	DebuggerPodNamePrefix       string   `yaml:"debuggerPodNamePrefix,omitempty"`
	DebuggerPodNamespace        string   `yaml:"debuggerPodNamespace,omitempty"`
	DebuggerImage               string   `yaml:"debuggerImage,omitempty"`
	DebuggerImagePullPolicy     string   `yaml:"debuggerImagePullPolicy,omitempty"`
	DebuggerImagePullSecretName string   `yaml:"debuggerImagePullSecretName,omitempty"`
	DebuggerPodCpuRequests      string   `yaml:"debuggerCpuRequests,omitempty"`
	DebuggerPodMemoryRequests   string   `yaml:"debuggerMemoryRequests,omitempty"`
	DebuggerPodCpuLimits        string   `yaml:"debuggerCpuLimits,omitempty"`
	DebuggerPodMemoryLimits     string   `yaml:"debuggerMemoryLimits,omitempty"`
	IsLxcfsEnabled              bool     `yaml:"isLxcfsEnabled,omitempty"`
	Verbosity                   int      `yaml:"verbosity,omitempty"`
	// deprecated
	DebuggerPortOld int `yaml:"debugger_port,omitempty"`
}

func Load(s string) (*Config, error) {
	cfg := &Config{}
	cfg.Debuggerless = true
	cfg.PortForward = true
	cfg.IsLxcfsEnabled = true
	err := yaml.Unmarshal([]byte(s), cfg)
	if err != nil {
		return nil, err
	}
	// be compatible with old configuration key
	if cfg.DebuggerPort == 0 {
		cfg.DebuggerPort = cfg.DebuggerPortOld
	}
	return cfg, nil
}

func LoadFile(filename string) (*Config, error) {
	c, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return Load(string(c))
}
