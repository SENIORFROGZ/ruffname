// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: common.proto

package otlppb

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// AnyValue is used to represent any type of attribute value. AnyValue may contain a
// primitive value such as a string or integer or it may contain an arbitrary nested
// object containing arrays, key-value lists and primitives.
type AnyValue struct {
	// The value is one of the listed fields. It is valid for all values to be unspecified
	// in which case this AnyValue is considered to be "null".
	//
	// Types that are valid to be assigned to Value:
	//	*AnyValue_StringValue
	//	*AnyValue_BoolValue
	//	*AnyValue_IntValue
	//	*AnyValue_DoubleValue
	//	*AnyValue_ArrayValue
	//	*AnyValue_KvlistValue
	Value isAnyValue_Value `protobuf_oneof:"value"`
}

func (m *AnyValue) Reset()                    { *m = AnyValue{} }
func (m *AnyValue) String() string            { return proto.CompactTextString(m) }
func (*AnyValue) ProtoMessage()               {}
func (*AnyValue) Descriptor() ([]byte, []int) { return fileDescriptorCommon, []int{0} }

type isAnyValue_Value interface {
	isAnyValue_Value()
}

type AnyValue_StringValue struct {
	StringValue string `protobuf:"bytes,1,opt,name=string_value,json=stringValue,proto3,oneof"`
}
type AnyValue_BoolValue struct {
	BoolValue bool `protobuf:"varint,2,opt,name=bool_value,json=boolValue,proto3,oneof"`
}
type AnyValue_IntValue struct {
	IntValue int64 `protobuf:"varint,3,opt,name=int_value,json=intValue,proto3,oneof"`
}
type AnyValue_DoubleValue struct {
	DoubleValue float64 `protobuf:"fixed64,4,opt,name=double_value,json=doubleValue,proto3,oneof"`
}
type AnyValue_ArrayValue struct {
	ArrayValue *ArrayValue `protobuf:"bytes,5,opt,name=array_value,json=arrayValue,oneof"`
}
type AnyValue_KvlistValue struct {
	KvlistValue *KeyValueList `protobuf:"bytes,6,opt,name=kvlist_value,json=kvlistValue,oneof"`
}

func (*AnyValue_StringValue) isAnyValue_Value() {}
func (*AnyValue_BoolValue) isAnyValue_Value()   {}
func (*AnyValue_IntValue) isAnyValue_Value()    {}
func (*AnyValue_DoubleValue) isAnyValue_Value() {}
func (*AnyValue_ArrayValue) isAnyValue_Value()  {}
func (*AnyValue_KvlistValue) isAnyValue_Value() {}

func (m *AnyValue) GetValue() isAnyValue_Value {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *AnyValue) GetStringValue() string {
	if x, ok := m.GetValue().(*AnyValue_StringValue); ok {
		return x.StringValue
	}
	return ""
}

func (m *AnyValue) GetBoolValue() bool {
	if x, ok := m.GetValue().(*AnyValue_BoolValue); ok {
		return x.BoolValue
	}
	return false
}

func (m *AnyValue) GetIntValue() int64 {
	if x, ok := m.GetValue().(*AnyValue_IntValue); ok {
		return x.IntValue
	}
	return 0
}

func (m *AnyValue) GetDoubleValue() float64 {
	if x, ok := m.GetValue().(*AnyValue_DoubleValue); ok {
		return x.DoubleValue
	}
	return 0
}

func (m *AnyValue) GetArrayValue() *ArrayValue {
	if x, ok := m.GetValue().(*AnyValue_ArrayValue); ok {
		return x.ArrayValue
	}
	return nil
}

func (m *AnyValue) GetKvlistValue() *KeyValueList {
	if x, ok := m.GetValue().(*AnyValue_KvlistValue); ok {
		return x.KvlistValue
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*AnyValue) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _AnyValue_OneofMarshaler, _AnyValue_OneofUnmarshaler, _AnyValue_OneofSizer, []interface{}{
		(*AnyValue_StringValue)(nil),
		(*AnyValue_BoolValue)(nil),
		(*AnyValue_IntValue)(nil),
		(*AnyValue_DoubleValue)(nil),
		(*AnyValue_ArrayValue)(nil),
		(*AnyValue_KvlistValue)(nil),
	}
}

func _AnyValue_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*AnyValue)
	// value
	switch x := m.Value.(type) {
	case *AnyValue_StringValue:
		_ = b.EncodeVarint(1<<3 | proto.WireBytes)
		_ = b.EncodeStringBytes(x.StringValue)
	case *AnyValue_BoolValue:
		t := uint64(0)
		if x.BoolValue {
			t = 1
		}
		_ = b.EncodeVarint(2<<3 | proto.WireVarint)
		_ = b.EncodeVarint(t)
	case *AnyValue_IntValue:
		_ = b.EncodeVarint(3<<3 | proto.WireVarint)
		_ = b.EncodeVarint(uint64(x.IntValue))
	case *AnyValue_DoubleValue:
		_ = b.EncodeVarint(4<<3 | proto.WireFixed64)
		_ = b.EncodeFixed64(math.Float64bits(x.DoubleValue))
	case *AnyValue_ArrayValue:
		_ = b.EncodeVarint(5<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.ArrayValue); err != nil {
			return err
		}
	case *AnyValue_KvlistValue:
		_ = b.EncodeVarint(6<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.KvlistValue); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("AnyValue.Value has unexpected type %T", x)
	}
	return nil
}

func _AnyValue_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*AnyValue)
	switch tag {
	case 1: // value.string_value
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Value = &AnyValue_StringValue{x}
		return true, err
	case 2: // value.bool_value
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Value = &AnyValue_BoolValue{x != 0}
		return true, err
	case 3: // value.int_value
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Value = &AnyValue_IntValue{int64(x)}
		return true, err
	case 4: // value.double_value
		if wire != proto.WireFixed64 {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeFixed64()
		m.Value = &AnyValue_DoubleValue{math.Float64frombits(x)}
		return true, err
	case 5: // value.array_value
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(ArrayValue)
		err := b.DecodeMessage(msg)
		m.Value = &AnyValue_ArrayValue{msg}
		return true, err
	case 6: // value.kvlist_value
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(KeyValueList)
		err := b.DecodeMessage(msg)
		m.Value = &AnyValue_KvlistValue{msg}
		return true, err
	default:
		return false, nil
	}
}

func _AnyValue_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*AnyValue)
	// value
	switch x := m.Value.(type) {
	case *AnyValue_StringValue:
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.StringValue)))
		n += len(x.StringValue)
	case *AnyValue_BoolValue:
		n += proto.SizeVarint(2<<3 | proto.WireVarint)
		n += 1
	case *AnyValue_IntValue:
		n += proto.SizeVarint(3<<3 | proto.WireVarint)
		n += proto.SizeVarint(uint64(x.IntValue))
	case *AnyValue_DoubleValue:
		n += proto.SizeVarint(4<<3 | proto.WireFixed64)
		n += 8
	case *AnyValue_ArrayValue:
		s := proto.Size(x.ArrayValue)
		n += proto.SizeVarint(5<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *AnyValue_KvlistValue:
		s := proto.Size(x.KvlistValue)
		n += proto.SizeVarint(6<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// ArrayValue is a list of AnyValue messages. We need ArrayValue as a message
// since oneof in AnyValue does not allow repeated fields.
type ArrayValue struct {
	// Array of values. The array may be empty (contain 0 elements).
	Values []*AnyValue `protobuf:"bytes,1,rep,name=values" json:"values,omitempty"`
}

func (m *ArrayValue) Reset()                    { *m = ArrayValue{} }
func (m *ArrayValue) String() string            { return proto.CompactTextString(m) }
func (*ArrayValue) ProtoMessage()               {}
func (*ArrayValue) Descriptor() ([]byte, []int) { return fileDescriptorCommon, []int{1} }

func (m *ArrayValue) GetValues() []*AnyValue {
	if m != nil {
		return m.Values
	}
	return nil
}

// KeyValueList is a list of KeyValue messages. We need KeyValueList as a message
// since `oneof` in AnyValue does not allow repeated fields. Everywhere else where we need
// a list of KeyValue messages (e.g. in Span) we use `repeated KeyValue` directly to
// avoid unnecessary extra wrapping (which slows down the protocol). The 2 approaches
// are semantically equivalent.
type KeyValueList struct {
	// A collection of key/value pairs of key-value pairs. The list may be empty (may
	// contain 0 elements).
	Values []*KeyValue `protobuf:"bytes,1,rep,name=values" json:"values,omitempty"`
}

func (m *KeyValueList) Reset()                    { *m = KeyValueList{} }
func (m *KeyValueList) String() string            { return proto.CompactTextString(m) }
func (*KeyValueList) ProtoMessage()               {}
func (*KeyValueList) Descriptor() ([]byte, []int) { return fileDescriptorCommon, []int{2} }

func (m *KeyValueList) GetValues() []*KeyValue {
	if m != nil {
		return m.Values
	}
	return nil
}

// KeyValue is a key-value pair that is used to store Span attributes, Link
// attributes, etc.
type KeyValue struct {
	Key   string    `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value *AnyValue `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
}

func (m *KeyValue) Reset()                    { *m = KeyValue{} }
func (m *KeyValue) String() string            { return proto.CompactTextString(m) }
func (*KeyValue) ProtoMessage()               {}
func (*KeyValue) Descriptor() ([]byte, []int) { return fileDescriptorCommon, []int{3} }

func (m *KeyValue) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *KeyValue) GetValue() *AnyValue {
	if m != nil {
		return m.Value
	}
	return nil
}

// StringKeyValue is a pair of key/value strings. This is the simpler (and faster) version
// of KeyValue that only supports string values.
type StringKeyValue struct {
	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (m *StringKeyValue) Reset()                    { *m = StringKeyValue{} }
func (m *StringKeyValue) String() string            { return proto.CompactTextString(m) }
func (*StringKeyValue) ProtoMessage()               {}
func (*StringKeyValue) Descriptor() ([]byte, []int) { return fileDescriptorCommon, []int{4} }

func (m *StringKeyValue) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *StringKeyValue) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

// InstrumentationLibrary is a message representing the instrumentation library information
// such as the fully qualified name and version.
type InstrumentationLibrary struct {
	// An empty instrumentation library name means the name is unknown.
	Name    string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Version string `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"`
}

func (m *InstrumentationLibrary) Reset()                    { *m = InstrumentationLibrary{} }
func (m *InstrumentationLibrary) String() string            { return proto.CompactTextString(m) }
func (*InstrumentationLibrary) ProtoMessage()               {}
func (*InstrumentationLibrary) Descriptor() ([]byte, []int) { return fileDescriptorCommon, []int{5} }

func (m *InstrumentationLibrary) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *InstrumentationLibrary) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func init() {
	proto.RegisterType((*AnyValue)(nil), "otlppb.AnyValue")
	proto.RegisterType((*ArrayValue)(nil), "otlppb.ArrayValue")
	proto.RegisterType((*KeyValueList)(nil), "otlppb.KeyValueList")
	proto.RegisterType((*KeyValue)(nil), "otlppb.KeyValue")
	proto.RegisterType((*StringKeyValue)(nil), "otlppb.StringKeyValue")
	proto.RegisterType((*InstrumentationLibrary)(nil), "otlppb.InstrumentationLibrary")
}

func init() { proto.RegisterFile("common.proto", fileDescriptorCommon) }

var fileDescriptorCommon = []byte{
	// 343 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0xc1, 0x4b, 0xc3, 0x30,
	0x14, 0xc6, 0x9b, 0x75, 0xeb, 0xda, 0xd7, 0x22, 0x23, 0x0c, 0xe9, 0x45, 0x2c, 0x15, 0xa4, 0xa7,
	0x1d, 0x26, 0x8a, 0x8a, 0x97, 0x89, 0x48, 0xc5, 0x9d, 0x22, 0x78, 0x95, 0x54, 0x8b, 0x84, 0xb5,
	0xc9, 0x48, 0xb3, 0x41, 0xff, 0x0a, 0xff, 0x65, 0x69, 0x92, 0xd6, 0x1d, 0xd4, 0x5b, 0xdf, 0xf7,
	0x7e, 0xdf, 0x7b, 0x1f, 0xaf, 0x81, 0xe8, 0x5d, 0xd4, 0xb5, 0xe0, 0x8b, 0xad, 0x14, 0x4a, 0x60,
	0x4f, 0xa8, 0x6a, 0xbb, 0x2d, 0xd2, 0xaf, 0x11, 0xf8, 0x2b, 0xde, 0xbe, 0xd2, 0x6a, 0x57, 0xe2,
	0x33, 0x88, 0x1a, 0x25, 0x19, 0xff, 0x7c, 0xdb, 0x77, 0x75, 0x8c, 0x12, 0x94, 0x05, 0xb9, 0x43,
	0x42, 0xa3, 0x1a, 0xe8, 0x14, 0xa0, 0x10, 0xa2, 0xb2, 0xc8, 0x28, 0x41, 0x99, 0x9f, 0x3b, 0x24,
	0xe8, 0x34, 0x03, 0x9c, 0x40, 0xc0, 0xb8, 0xb2, 0x7d, 0x37, 0x41, 0x99, 0x9b, 0x3b, 0xc4, 0x67,
	0x5c, 0x0d, 0x4b, 0x3e, 0xc4, 0xae, 0xa8, 0x4a, 0x4b, 0x8c, 0x13, 0x94, 0xa1, 0x6e, 0x89, 0x51,
	0x0d, 0x74, 0x09, 0x21, 0x95, 0x92, 0xb6, 0x96, 0x99, 0x24, 0x28, 0x0b, 0x97, 0x78, 0x61, 0x42,
	0x2f, 0x56, 0x5d, 0x4b, 0x83, 0xb9, 0x43, 0x80, 0x0e, 0x15, 0xbe, 0x81, 0x68, 0xb3, 0xaf, 0x58,
	0xd3, 0x6f, 0xf7, 0xb4, 0x6f, 0xde, 0xfb, 0x9e, 0x4b, 0xc3, 0xad, 0x59, 0xa3, 0xba, 0x8d, 0x86,
	0xd5, 0xd2, 0xfd, 0x14, 0x26, 0xda, 0x93, 0x5e, 0x01, 0xfc, 0xcc, 0xc7, 0x19, 0x78, 0x5a, 0x6e,
	0x62, 0x94, 0xb8, 0x59, 0xb8, 0x9c, 0x0d, 0x19, 0xec, 0xd1, 0x88, 0xed, 0xa7, 0xd7, 0x10, 0x1d,
	0xce, 0xff, 0xdb, 0xd9, 0x53, 0x83, 0xf3, 0x01, 0xfc, 0x5e, 0xc3, 0x33, 0x70, 0x37, 0x65, 0x6b,
	0x2e, 0x4f, 0xba, 0x4f, 0x7c, 0x6e, 0x83, 0xe9, 0x53, 0xff, 0x16, 0xc0, 0xe6, 0xbe, 0x83, 0xa3,
	0x17, 0xfd, 0x9b, 0xfe, 0x99, 0x35, 0x3f, 0x9c, 0x15, 0x58, 0xe7, 0xed, 0x28, 0x46, 0xe9, 0x23,
	0x1c, 0x3f, 0xf1, 0x46, 0xc9, 0x5d, 0x5d, 0x72, 0x45, 0x15, 0x13, 0x7c, 0xcd, 0x0a, 0x49, 0x65,
	0x8b, 0x31, 0x8c, 0x39, 0xad, 0xed, 0x63, 0x20, 0xfa, 0x1b, 0xc7, 0x30, 0xdd, 0x97, 0xb2, 0x61,
	0x82, 0xdb, 0x49, 0x7d, 0x59, 0x78, 0xfa, 0x79, 0x5d, 0x7c, 0x07, 0x00, 0x00, 0xff, 0xff, 0xaf,
	0xf5, 0x8e, 0xdc, 0x6e, 0x02, 0x00, 0x00,
}
