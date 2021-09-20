// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2019 Datadog, Inc.

// +build python

package python

import (
	"expvar"
	"sync"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

/*
#cgo !windows LDFLAGS: -ldatadog-agent-rtloader -ldl
#cgo windows LDFLAGS: -ldatadog-agent-rtloader -lstdc++ -static

#include "datadog_agent_rtloader.h"
#include "rtloader_mem.h"
*/
import (
	"C"
)

var (
	pointerCache = sync.Map{}

	rtLoaderExpvars = expvar.NewMap("rtloader")
	inuseBytes      = expvar.Int{}
	allocatedBytes  = expvar.Int{}
	freedBytes      = expvar.Int{}
	allocations     = expvar.Int{}
	frees           = expvar.Int{}
	untrackedFrees  = expvar.Int{}
)

func init() {
	rtLoaderExpvars.Set("InuseBytes", &inuseBytes)
	rtLoaderExpvars.Set("AllocatedBytes", &allocatedBytes)
	rtLoaderExpvars.Set("FreedBytes", &freedBytes)
	rtLoaderExpvars.Set("Allocations", &allocations)
	rtLoaderExpvars.Set("Frees", &frees)
	rtLoaderExpvars.Set("UntrackedFrees", &untrackedFrees)
}

// MemoryTracker is the method exposed to the RTLoader for memory tracking
//export MemoryTracker
func MemoryTracker(ptr unsafe.Pointer, sz C.size_t, op C.rtloader_mem_ops_t, backtrace **C.char, frames C.int) {
	// run async for performance reasons
	go func() {
		log.Debugf("Memory Tracker - ptr: %v, sz: %v, op: %v", ptr, sz, op)
		if backtrace != nil {
			log.Debugf("backtrace sample available:")
			frame := backtrace
			for i := 0; i < int(frames); i++ {
				log.Debugf("frame %v: %v", i, C.GoString(*frame))
				frame = (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(frame)) + unsafe.Sizeof(*frame)))
			}
		}
		switch op {
		case C.DATADOG_AGENT_RTLOADER_ALLOCATION:
			pointerCache.Store(ptr, sz)
			allocations.Add(1)
			allocatedBytes.Add(int64(sz))
			inuseBytes.Add(int64(sz))

		case C.DATADOG_AGENT_RTLOADER_FREE:
			bytes, ok := pointerCache.Load(ptr)
			if !ok {
				log.Warnf("untracked memory was attempted to be freed")
				untrackedFrees.Add(1)
				return
			}
			defer pointerCache.Delete(ptr)

			frees.Add(1)
			freedBytes.Add(int64(bytes.(C.size_t)))
			inuseBytes.Add(-1 * int64(bytes.(C.size_t)))
		}
	}()
}

func TrackedCString(str string) *C.char {
	cstr := C.CString(str)
	MemoryTracker(unsafe.Pointer(cstr), C.size_t(len(str)+1), C.DATADOG_AGENT_RTLOADER_ALLOCATION, nil, 0)

	return cstr
}
