// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2019 Datadog, Inc.

// +build python

package python

import (
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/tagger"
	"github.com/DataDog/datadog-agent/pkg/tagger/collectors"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

/*
#include <datadog_agent_rtloader.h>
#cgo !windows LDFLAGS: -ldatadog-agent-rtloader -ldl
#cgo windows LDFLAGS: -ldatadog-agent-rtloader -lstdc++ -static
*/
import "C"

// for testing purposes
var (
	tagsFunc = tagger.Tag
)

// Tags bridges towards tagger.Tag to retrieve container tags
//export Tags
func Tags(id *C.char, cardinality C.int) **C.char {
	goID := C.GoString(id)
	var tags []string

	tags, _ = tagsFunc(goID, collectors.TagCardinality(cardinality))

	length := len(tags)
	if length == 0 {
		return nil
	}

	cTags := C.malloc(C.size_t(length+1) * C.size_t(unsafe.Sizeof(uintptr(0))))
	if cTags == nil {
		log.Errorf("could not allocate memory for tags")
		return nil
	}

	// convert the C array to a Go Array so we can index it
	indexTag := (*[1<<29 - 1]*C.char)(cTags)[: length+1 : length+1]
	indexTag[length] = nil
	for idx, tag := range tags {
		indexTag[idx] = C.CString(tag)
	}

	return (**C.char)(cTags)
}
