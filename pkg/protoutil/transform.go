package protoutil

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type TransformFunc func(protoreflect.FieldDescriptor, protoreflect.Value) (protoreflect.Value, error)

func Transform(msg proto.Message, f TransformFunc) (proto.Message, error) {
}
