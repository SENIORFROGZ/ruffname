// Code generated by mockery v2.2.1. DO NOT EDIT.

package mocks

import (
	event "github.com/DataDog/datadog-agent/pkg/compliance/event"
	mock "github.com/stretchr/testify/mock"
)

// Reporter is an autogenerated mock type for the Reporter type
type Reporter struct {
	mock.Mock
}

// Report provides a mock function with given fields: _a0
func (_m *Reporter) Report(_a0 *event.Event) {
	_m.Called(_a0)
}

// ReportRaw provides a mock function with given fields: _a0
func (_m *Reporter) ReportRaw(_a0 []byte) {
	_m.Called(_a0)
}
