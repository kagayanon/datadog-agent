// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

package config

import (
	"fmt"
	"net"
	"strconv"

	"github.com/DataDog/datadog-agent/pkg/config"
)

// LogsAgent is the global configuration object
var LogsAgent = config.Datadog

// Build returns logs-agent sources
func Build() (*LogSources, *ServerConfig, error) {
	sources, err := buildLogSources(
		LogsAgent.GetString("confd_path"),
		LogsAgent.GetBool("logs_config.container_collect_all"),
		LogsAgent.GetInt("logs_config.tcp_forward_port"),
	)
	if err != nil {
		return nil, nil, err
	}
	serverConfig, err := buildServerConfig()
	if err != nil {
		return nil, nil, err
	}
	return sources, serverConfig, nil
}

// buildLogSources returns all the logs sources computed from logs configuration files and environment variables
func buildLogSources(ddconfdPath string, collectAllLogsFromContainers bool, tcpForwardPort int) (*LogSources, error) {
	var sources []*LogSource

	// append sources from all logs config files
	fileSources := buildLogSourcesFromDirectory(ddconfdPath)
	sources = append(sources, fileSources...)

	if collectAllLogsFromContainers {
		// append source to collect all logs from all containers.
		containersSource := NewLogSource("container_collect_all", &LogsConfig{
			Type:    DockerType,
			Service: "docker",
			Source:  "docker",
		})
		sources = append(sources, containersSource)
	}

	if tcpForwardPort > 0 {
		// append source to collect all logs forwarded by TCP on a given port.
		tcpForwardSource := NewLogSource("tcp_forward", &LogsConfig{
			Type: TCPType,
			Port: tcpForwardPort,
		})
		sources = append(sources, tcpForwardSource)
	}

	logSources := NewLogSources(sources)
	if len(logSources.GetValidSources()) == 0 {
		return nil, fmt.Errorf("could not find any valid logs configuration")
	}

	return logSources, nil
}

// buildServerConfig returns the server config to send logs to.
func buildServerConfig() (*ServerConfig, error) {
	switch {
	case LogsAgent.GetString("logs_config.logs_dd_url") != "":
		host, portString, err := net.SplitHostPort(LogsAgent.GetString("logs_config.logs_dd_url"))
		if err != nil {
			return nil, fmt.Errorf("could not parse logs_dd_url: %v", err)
		}
		port, err := strconv.Atoi(portString)
		if err != nil {
			return nil, fmt.Errorf("could not parse logs_dd_url port: %v", err)
		}
		return NewServerConfig(
			host,
			port,
			!LogsAgent.GetBool("logs_config.logs_no_ssl"),
		), nil
	default:
		return NewServerConfig(
			LogsAgent.GetString("logs_config.dd_url"),
			LogsAgent.GetInt("logs_config.dd_port"),
			!LogsAgent.GetBool("logs_config.dev_mode_no_ssl"),
		), nil
	}
}
