// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package cgroups

import "fmt"

type InvalidInputError struct {
	Desc string
}

func (e *InvalidInputError) Error() string {
	return "invalid input: " + e.Desc
}

type ControllerNotFoundError struct {
	Controller string
}

func (e *ControllerNotFoundError) Error() string {
	return "mount point for cgroup controller not found: " + e.Controller
}

func (e *ControllerNotFoundError) Is(target error) bool {
	t, ok := target.(*ControllerNotFoundError)
	if !ok {
		return false
	}
	return e.Controller == t.Controller
}

type FileSystemError struct {
	FilePath string
	Err      error
}

func newFileSystemError(path string, err error) *FileSystemError {
	return &FileSystemError{
		FilePath: path,
		Err:      err,
	}
}

func (e *FileSystemError) Error() string {
	return fmt.Sprintf("fs error, path: %s, err: %s", e.FilePath, e.Err.Error())
}

func (e *FileSystemError) Unwrap() error {
	return e.Err
}

type ValueError struct {
	Data string
	Err  error
}

func newValueError(data string, err error) *ValueError {
	return &ValueError{
		Data: data,
		Err:  err,
	}
}

func (e *ValueError) Error() string {
	return fmt.Sprintf("value error, data: '%s', err: %s", e.Data, e.Err.Error())
}

func (e *ValueError) Unwrap() error {
	return e.Err
}
