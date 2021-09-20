// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trace_service.proto

package otlppb

import (
	fmt "fmt"
	math "math"

	proto "github.com/gogo/protobuf/proto"
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type ExportTraceServiceRequest struct {
	// An array of ResourceSpans.
	// For data coming from a single resource this array will typically contain one
	// element. Intermediary nodes (such as OpenTelemetry Collector) that receive
	// data from multiple origins typically batch the data before forwarding further and
	// in that case this array will contain multiple elements.
	ResourceSpans []*ResourceSpans `protobuf:"bytes,1,rep,name=resource_spans,json=resourceSpans" json:"resource_spans,omitempty"`
}

func (m *ExportTraceServiceRequest) Reset()         { *m = ExportTraceServiceRequest{} }
func (m *ExportTraceServiceRequest) String() string { return proto.CompactTextString(m) }
func (*ExportTraceServiceRequest) ProtoMessage()    {}
func (*ExportTraceServiceRequest) Descriptor() ([]byte, []int) {
	return fileDescriptorTraceService, []int{0}
}

func (m *ExportTraceServiceRequest) GetResourceSpans() []*ResourceSpans {
	if m != nil {
		return m.ResourceSpans
	}
	return nil
}

type ExportTraceServiceResponse struct {
}

func (m *ExportTraceServiceResponse) Reset()         { *m = ExportTraceServiceResponse{} }
func (m *ExportTraceServiceResponse) String() string { return proto.CompactTextString(m) }
func (*ExportTraceServiceResponse) ProtoMessage()    {}
func (*ExportTraceServiceResponse) Descriptor() ([]byte, []int) {
	return fileDescriptorTraceService, []int{1}
}

func init() {
	proto.RegisterType((*ExportTraceServiceRequest)(nil), "otlppb.ExportTraceServiceRequest")
	proto.RegisterType((*ExportTraceServiceResponse)(nil), "otlppb.ExportTraceServiceResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for TraceService service

type TraceServiceClient interface {
	// For performance reasons, it is recommended to keep this RPC
	// alive for the entire life of the application.
	Export(ctx context.Context, in *ExportTraceServiceRequest, opts ...grpc.CallOption) (*ExportTraceServiceResponse, error)
}

type traceServiceClient struct {
	cc *grpc.ClientConn
}

func NewTraceServiceClient(cc *grpc.ClientConn) TraceServiceClient {
	return &traceServiceClient{cc}
}

func (c *traceServiceClient) Export(ctx context.Context, in *ExportTraceServiceRequest, opts ...grpc.CallOption) (*ExportTraceServiceResponse, error) {
	out := new(ExportTraceServiceResponse)
	err := grpc.Invoke(ctx, "/otlppb.TraceService/Export", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for TraceService service

type TraceServiceServer interface {
	// For performance reasons, it is recommended to keep this RPC
	// alive for the entire life of the application.
	Export(context.Context, *ExportTraceServiceRequest) (*ExportTraceServiceResponse, error)
}

func RegisterTraceServiceServer(s *grpc.Server, srv TraceServiceServer) {
	s.RegisterService(&_TraceService_serviceDesc, srv)
}

func _TraceService_Export_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExportTraceServiceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TraceServiceServer).Export(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/otlppb.TraceService/Export",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TraceServiceServer).Export(ctx, req.(*ExportTraceServiceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _TraceService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "opentelemetry.proto.collector.trace.v1.TraceService",
	HandlerType: (*TraceServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Export",
			Handler:    _TraceService_Export_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "trace_service.proto",
}

func init() { proto.RegisterFile("trace_service.proto", fileDescriptorTraceService) }

var fileDescriptorTraceService = []byte{
	// 165 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0x2e, 0x29, 0x4a, 0x4c,
	0x4e, 0x8d, 0x2f, 0x4e, 0x2d, 0x2a, 0xcb, 0x4c, 0x4e, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17,
	0x62, 0xcb, 0x2f, 0xc9, 0x29, 0x28, 0x48, 0x92, 0xe2, 0x06, 0x4b, 0x42, 0x04, 0x95, 0x22, 0xb9,
	0x24, 0x5d, 0x2b, 0x0a, 0xf2, 0x8b, 0x4a, 0x42, 0x40, 0x82, 0xc1, 0x10, 0x0d, 0x41, 0xa9, 0x85,
	0xa5, 0xa9, 0xc5, 0x25, 0x42, 0x36, 0x5c, 0x7c, 0x45, 0xa9, 0xc5, 0xf9, 0xa5, 0x45, 0x20, 0xb3,
	0x0a, 0x12, 0xf3, 0x8a, 0x25, 0x18, 0x15, 0x98, 0x35, 0xb8, 0x8d, 0x44, 0xf5, 0x20, 0x46, 0xe9,
	0x05, 0x41, 0x65, 0x83, 0x41, 0x92, 0x41, 0xbc, 0x45, 0xc8, 0x5c, 0x25, 0x19, 0x2e, 0x29, 0x6c,
	0x46, 0x17, 0x17, 0xe4, 0xe7, 0x15, 0xa7, 0x1a, 0x25, 0x72, 0xf1, 0x20, 0x8b, 0x0b, 0x05, 0x72,
	0xb1, 0x41, 0x54, 0x0b, 0x29, 0xc2, 0x4c, 0xc7, 0xe9, 0x30, 0x29, 0x25, 0x7c, 0x4a, 0x20, 0x16,
	0x28, 0x31, 0x24, 0xb1, 0x81, 0xbd, 0x68, 0x0c, 0x08, 0x00, 0x00, 0xff, 0xff, 0x0f, 0xc1, 0x71,
	0x77, 0x0e, 0x01, 0x00, 0x00,
}
