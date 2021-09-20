// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

// +build !windows

package listener

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline/mock"
)

const maxUDPFrameLen = 65535

func TestUDPShouldProperlyTruncateBigMessages(t *testing.T) {
	pp := mock.NewMockProvider()
	msgChan := pp.NextPipelineChan()
	listener := NewUDPListener(pp, config.NewLogSource("", &config.LogsConfig{Port: udpTestPort}), defaultFrameSize)
	listener.Start()

	conn, err := net.Dial("udp", fmt.Sprintf("localhost:%d", udpTestPort))
	assert.Nil(t, err)

	var msg message.Message

	fmt.Fprintf(conn, strings.Repeat("a", defaultFrameSize-100)+"\n")
	msg = <-msgChan
	assert.Equal(t, strings.Repeat("a", defaultFrameSize-100), string(msg.Content()))

	fmt.Fprintf(conn, strings.Repeat("a", defaultFrameSize)+"\n")
	msg = <-msgChan
	assert.Equal(t, strings.Repeat("a", defaultFrameSize), string(msg.Content()))

	fmt.Fprintf(conn, strings.Repeat("a", defaultFrameSize-200)+"\n")
	msg = <-msgChan
	assert.Equal(t, strings.Repeat("a", defaultFrameSize-200), string(msg.Content()))

	listener.Stop()
}

func TestUDPShoulDropTooBigMessages(t *testing.T) {
	pp := mock.NewMockProvider()
	msgChan := pp.NextPipelineChan()
	listener := NewUDPListener(pp, config.NewLogSource("", &config.LogsConfig{Port: udpTestPort}), maxUDPFrameLen)
	listener.Start()

	conn, err := net.Dial("udp", fmt.Sprintf("localhost:%d", udpTestPort))
	assert.Nil(t, err)

	var msg message.Message

	fmt.Fprintf(conn, strings.Repeat("a", maxUDPFrameLen-100)+"\n")
	msg = <-msgChan
	assert.Equal(t, strings.Repeat("a", maxUDPFrameLen-100), string(msg.Content()))

	// the first frame should be dropped as it's too big compare to the limit.
	fmt.Fprintf(conn, strings.Repeat("a", maxUDPFrameLen+100)+"\n")
	fmt.Fprintf(conn, strings.Repeat("a", maxUDPFrameLen-200)+"\n")
	msg = <-msgChan
	assert.Equal(t, strings.Repeat("a", maxUDPFrameLen-200), string(msg.Content()))

	listener.Stop()
}
