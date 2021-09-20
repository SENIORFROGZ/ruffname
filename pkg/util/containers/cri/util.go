// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build cri

package cri

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/retry"
	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

var (
	globalCRIUtil *CRIUtil
	once          sync.Once
)

type CRIClient interface {
	ListContainerStats() (map[string]*pb.ContainerStats, error)
	GetContainerStatus(containerID string) (*pb.ContainerStatus, error)
	GetRuntime() string
	GetRuntimeVersion() string
}

// CRIUtil wraps interactions with the CRI and implements CRIClient
// see https://github.com/kubernetes/kubernetes/blob/release-1.12/pkg/kubelet/apis/cri/runtime/v1alpha2/api.proto
type CRIUtil struct {
	// used to setup the CRIUtil
	initRetry retry.Retrier

	sync.Mutex
	client            pb.RuntimeServiceClient
	runtime           string
	runtimeVersion    string
	queryTimeout      time.Duration
	connectionTimeout time.Duration
	socketPath        string
}

// init makes an empty CRIUtil bootstrap itself.
// This is not exposed as public API but is called by the retrier embed.
func (c *CRIUtil) init() error {
	if c.socketPath == "" {
		return fmt.Errorf("no cri_socket_path was set")
	}

	dialer := func(socketPath string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("unix", socketPath, timeout)
	}

	conn, err := grpc.Dial(c.socketPath, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(c.connectionTimeout), grpc.WithDialer(dialer))
	if err != nil {
		return fmt.Errorf("failed to dial: %v", err)
	}

	c.client = pb.NewRuntimeServiceClient(conn)
	// validating the connection by fetching the version
	ctx, cancel := context.WithTimeout(context.Background(), c.connectionTimeout)
	defer cancel()
	request := &pb.VersionRequest{}
	r, err := c.client.Version(ctx, request)
	if err != nil {
		return err
	}
	c.runtime = r.RuntimeName
	c.runtimeVersion = r.RuntimeVersion
	log.Debugf("Successfully connected to CRI %s %s", c.runtime, c.runtimeVersion)

	return nil
}

// GetUtil returns a ready to use CRIUtil. It is backed by a shared singleton.
func GetUtil() (*CRIUtil, error) {
	once.Do(func() {
		globalCRIUtil = &CRIUtil{
			queryTimeout:      config.Datadog.GetDuration("cri_query_timeout") * time.Second,
			connectionTimeout: config.Datadog.GetDuration("cri_connection_timeout") * time.Second,
			socketPath:        config.Datadog.GetString("cri_socket_path"),
		}
		globalCRIUtil.initRetry.SetupRetrier(&retry.Config{ //nolint:errcheck
			Name:              "criutil",
			AttemptMethod:     globalCRIUtil.init,
			Strategy:          retry.Backoff,
			InitialRetryDelay: 1 * time.Second,
			MaxRetryDelay:     5 * time.Minute,
		})
	})

	if err := globalCRIUtil.initRetry.TriggerRetry(); err != nil {
		log.Debugf("CRI init error: %s", err)
		return nil, err
	}
	return globalCRIUtil, nil
}

// ListContainerStats sends a ListContainerStatsRequest to the server, and parses the returned response
func (c *CRIUtil) ListContainerStats() (map[string]*pb.ContainerStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.queryTimeout)
	defer cancel()
	filter := &pb.ContainerStatsFilter{}
	request := &pb.ListContainerStatsRequest{Filter: filter}
	r, err := c.client.ListContainerStats(ctx, request)
	if err != nil {
		return nil, err
	}

	stats := make(map[string]*pb.ContainerStats)
	for _, s := range r.GetStats() {
		stats[s.Attributes.Id] = s
	}
	return stats, nil
}

// GetContainerStatus requests a container status by its ID
func (c *CRIUtil) GetContainerStatus(containerID string) (*pb.ContainerStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.queryTimeout)
	defer cancel()
	request := &pb.ContainerStatusRequest{ContainerId: containerID}
	r, err := c.client.ContainerStatus(ctx, request)
	if err != nil {
		return nil, err
	}

	return r.Status, nil
}

func (c *CRIUtil) GetRuntime() string {
	return c.runtime
}

func (c *CRIUtil) GetRuntimeVersion() string {
	return c.runtimeVersion
}
