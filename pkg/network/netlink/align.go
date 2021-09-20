// +build linux
// +build !android

package netlink

import (
	"unsafe"

	"github.com/mdlayher/netlink"
)

// Copyright (C) 2016-2021 Matt Layher
// Source https://github.com/mdlayher/netlink/blob/ec511443387bb32b3adcd448828476c83754c8e8/align.go
// Functions and values used to properly align netlink messages, headers,
// and attributes. Definitions taken from Linux kernel source.

// #define NLMSG_ALIGNTO 4U
const nlmsgAlignTo = 4

// #define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
func nlmsgAlign(len int) int {
	return ((len) + nlmsgAlignTo - 1) & ^(nlmsgAlignTo - 1)
}

// #define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
//nolint:unused,deadcode
func nlmsgLength(len int) int {
	return len + nlmsgHeaderLen
}

// #define NLMSG_HDRLEN ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
//nolint:unused
var nlmsgHeaderLen = nlmsgAlign(int(unsafe.Sizeof(netlink.Header{})))

// #define NLA_ALIGNTO 4
const nlaAlignTo = 4

// #define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
func nlaAlign(len int) int {
	return ((len) + nlaAlignTo - 1) & ^(nlaAlignTo - 1)
}

// Because this package's Attribute type contains a byte slice, unsafe.Sizeof
// can't be used to determine the correct length.
const sizeofAttribute = 4

// #define NLA_HDRLEN ((int) NLA_ALIGN(sizeof(struct nlattr)))
var nlaHeaderLen = nlaAlign(sizeofAttribute)
