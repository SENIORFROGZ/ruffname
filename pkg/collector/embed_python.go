// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2019 Datadog, Inc.

// +build python

package collector

import (
	"github.com/DataDog/datadog-agent/pkg/collector/python"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func pySetup(paths ...string) (pythonVersion, pythonHome, pythonPath string) {
	if err := python.Initialize(paths...); err != nil {
		log.Errorf("Could not initialize Python: %s", err)
	}
	log.Infof("Python init done: %s | %s | %s", python.PythonVersion, python.PythonHome, python.PythonPath)
	return python.PythonVersion, python.PythonHome, python.PythonPath
}

func pyPrepareEnv() error {
	//if config.Datadog.IsSet("procfs_path") {
	//	procfsPath := config.Datadog.GetString("procfs_path")
	//	err := py.SetPythonPsutilProcPath(procfsPath)
	//	if err != nil {
	//		return err
	//	}
	//}

	return nil
}

func pyTeardown() {
	python.Destroy()
}
