// Copyright 2012 Andreas Louca, 2013 Sonia Hamilton, 2014 Nathan Owens. All rights reserved.  Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

func decodeValue(data []byte, msg string) (retVal *Variable, err error) {
	dumpBytes1(data, fmt.Sprintf("decodeValue: %s", msg), 16)
	retVal = new(Variable)

	switch ASN1BER(data[0]) {

	case Integer:
		// 0x02. signed
		slog.Print("decodeValue: type is Integer")
		length, cursor := parseLength(data)
		if ret, err := parseInt(data[cursor:length]); err != nil {
			slog.Printf("%v:", err)
			return retVal, fmt.Errorf("bytes: % x err: %v", data, err)
		} else {
			retVal.Type = Integer
			retVal.Value = ret
		}
	case OctetString:
		// 0x04
		slog.Print("decodeValue: type is OctetString")
		length, cursor := parseLength(data)
		retVal.Type = OctetString
		if data[cursor] == 0 && length == 2 {
			retVal.Value = ""
		} else if data[cursor] == 0 {
			retVal.Value = fmt.Sprintf("% x", data[cursor:length])
		} else {
			retVal.Value = string(data[cursor:length])
		}
	case Null:
		// 0x05
		slog.Print("decodeValue: type is Null")
		retVal.Type = Null
		retVal.Value = nil
	case ObjectIdentifier:
		// 0x06
		slog.Print("decodeValue: type is ObjectIdentifier")
		rawOid, _, err := parseRawField(data, "OID")
		if err != nil {
			return nil, fmt.Errorf("Error parsing OID Value: %s", err.Error())
		}
		var oid []int
		var ok bool
		if oid, ok = rawOid.([]int); !ok {
			return nil, fmt.Errorf("unable to type assert rawOid |%v| to []int", rawOid)
		}
		retVal.Type = ObjectIdentifier
		retVal.Value = oidToString(oid)
	case IPAddress:
		// 0x40
		slog.Print("decodeValue: type is IpAddress")
		//TODO: IPv6 support!
		if len(data) < 6 {
			return nil, fmt.Errorf("not enough data for ipaddress: % x", data)
		} else if data[1] != 4 {
			return nil, fmt.Errorf("got ipaddress len %d, expected 4", data[1])
		}
		retVal.Type = IPAddress
		var IPv4 string
		for i := 2; i < 6; i++ {
			IPv4 += fmt.Sprintf(".%d", data[i])
		}
		retVal.Value = IPv4[1:]
	case Counter32:
		// 0x41. unsigned
		slog.Print("decodeValue: type is Counter32")
		length, cursor := parseLength(data)
		ret, err := parseUint(data[cursor:length])
		if err != nil {
			slog.Printf("decodeValue: err is %v", err)
			break
		}
		retVal.Type = Counter32
		retVal.Value = ret
	case Gauge32:
		// 0x42. unsigned
		slog.Print("decodeValue: type is Gauge32")
		length, cursor := parseLength(data)
		ret, err := parseUint(data[cursor:length])
		if err != nil {
			slog.Printf("decodeValue: err is %v", err)
			break
		}
		retVal.Type = Gauge32
		retVal.Value = ret
	case TimeTicks:
		// 0x43
		slog.Print("decodeValue: type is TimeTicks")
		length, cursor := parseLength(data)
		ret, err := parseInt(data[cursor:length])
		if err != nil {
			slog.Printf("decodeValue: err is %v", err)
			break
		}
		retVal.Type = TimeTicks
		retVal.Value = ret
	case Counter64:
		// 0x46
		slog.Print("decodeValue: type is Counter64")
		length, cursor := parseLength(data)
		ret, err := parseInt64(data[cursor:length])
		if err != nil {
			slog.Printf("decodeValue: err is %v", err)
			break
		}
		retVal.Type = Counter64
		retVal.Value = ret
	case NoSuchObject:
		// 0x80
		slog.Print("decodeValue: type is NoSuchObject")
		retVal.Type = NoSuchObject
		retVal.Value = nil
	case NoSuchInstance:
		// 0x81
		slog.Print("decodeValue: type is NoSuchInstance")
		retVal.Type = NoSuchInstance
		retVal.Value = nil
	case EndOfMibView:
		// 0x82
		slog.Print("decodeValue: type is EndOfMibView")
		retVal.Type = EndOfMibView
		retVal.Value = nil
	default:
		slog.Printf("decodeValue: type %x isn't implemented", data[0])
		retVal.Type = UnknownType
		retVal.Value = nil
	}

	slog.Printf("decodeValue: value is %#v", retVal.Value)
	return
}

//dump bytes in a format similar to Wireshark
func dumpBytes1(data []byte, msg string, maxlength int) {
	for i, b := range data {
		if i >= maxlength {
			break
		}
		if (i % 8) == 0 {
			msg += "\n"
			msg += fmt.Sprintf("%3d ", i)
		} else if i == 0 {
			msg += fmt.Sprintf("%3d ", 0)
		}
		msg += fmt.Sprintf(" %02x", b)
	}
	slog.Print(msg)
}

// dump bytes in one row, up to about screen width. Returns a string
// rather than (dumpBytes1) writing to debugging log.
func dumpBytes2(desc string, bb []byte, cursor int) string {
	cursor = cursor - 4 // give some context to dump
	if cursor < 0 {
		cursor = 0
	}
	result := desc
	for i, b := range bb[cursor:] {
		if i > 30 { // about screen width...
			break
		}
		result += fmt.Sprintf(" %02x", b)
	}
	return result
}

func marshalBase128Int(out *bytes.Buffer, n int64) (err error) {
	if n == 0 {
		err = out.WriteByte(0)
		return
	}

	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}

	for i := l - 1; i >= 0; i-- {
		o := byte(n >> uint(i*7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}
		err = out.WriteByte(o)
		if err != nil {
			return
		}
	}

	return nil
}

func oidToString(oid []int) (ret string) {
	values := make([]interface{}, len(oid))
	for i, v := range oid {
		values[i] = v
	}
	return fmt.Sprintf(strings.Repeat(".%d", len(oid)), values...)
}

// parseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice. It returns the value and the new offset.
func parseBase128Int(bytes []byte, initOffset int) (ret, offset int, err error) {
	offset = initOffset
	for shifted := 0; offset < len(bytes); shifted++ {
		if shifted > 4 {
			err = fmt.Errorf("Structural Error: base 128 integer too large")
			return
		}
		ret <<= 7
		b := bytes[offset]
		ret |= int(b & 0x7f)
		offset++
		if b&0x80 == 0 {
			return
		}
	}
	err = fmt.Errorf("Syntax Error: truncated base 128 integer")
	return
}

// parseBitString parses an ASN.1 bit string from the given byte slice and returns it.
func parseBitString(bytes []byte) (ret BitStringValue, err error) {
	if len(bytes) == 0 {
		err = errors.New("zero length BIT STRING")
		return
	}
	paddingBits := int(bytes[0])
	if paddingBits > 7 ||
		len(bytes) == 1 && paddingBits > 0 ||
		bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
		err = errors.New("invalid padding bits in BIT STRING")
		return
	}
	ret.BitLength = (len(bytes)-1)*8 - paddingBits
	ret.Bytes = bytes[1:]
	return
}

// parseInt64 treats the given bytes as a big-endian, signed integer and
// returns the result.
func parseInt64(bytes []byte) (ret int64, err error) {
	if len(bytes) > 8 {
		// We'll overflow an int64 in this case.
		err = errors.New("integer too large")
		return
	}
	for bytesRead := 0; bytesRead < len(bytes); bytesRead++ {
		ret <<= 8
		ret |= int64(bytes[bytesRead])
	}

	// Shift up and down in order to sign extend the result.
	ret <<= 64 - uint8(len(bytes))*8
	ret >>= 64 - uint8(len(bytes))*8
	return
}

// parseInt treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseInt(bytes []byte) (int, error) {
	ret64, err := parseInt64(bytes)
	if err != nil {
		return 0, err
	}
	if ret64 != int64(int(ret64)) {
		return 0, errors.New("integer too large")
	}
	return int(ret64), nil
}

// parseLength parses and calculates an snmp packet lengths
// http://luca.ntop.org/Teaching/Appunti/asn1.html
//
// Length octets. There are two forms: short (for lengths between 0 and 127),
// and long definite (for lengths between 0 and 2^1008 -1).
//
// * Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
// * Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits
//   7-1 give the number of additional length octets. Second and following
//   octets give the length, base 256, most significant digit first.
func parseLength(bytes []byte) (length int, cursor int) {
	if len(bytes) <= 2 {
		// handle null octet strings ie "0x04 0x00"
		cursor = 1
		length = 2
	} else if int(bytes[1]) <= 127 {
		length = int(bytes[1])
		length += 2
		cursor += 2
	} else {
		numOctets := int(bytes[1]) & 127
		for i := 0; i < numOctets; i++ {
			length <<= 8
			length += int(bytes[2+i])
		}
		length += 2 + numOctets
		cursor += 2 + numOctets
	}
	return length, cursor
}

// parseObjectIdentifier parses an OBJECT IDENTIFIER from the given bytes and
// returns it. An object identifier is a sequence of variable length integers
// that are assigned in a hierarchy.
func parseObjectIdentifier(bytes []byte) (s []int, err error) {
	if len(bytes) == 0 {
		err = fmt.Errorf("zero length OBJECT IDENTIFIER")
		return
	}

	// In the worst case, we get two elements from the first byte (which is
	// encoded differently) and then every varint is a single byte long.
	s = make([]int, len(bytes)+1)

	// The first byte is 40*value1 + value2:
	s[0] = int(bytes[0]) / 40
	s[1] = int(bytes[0]) % 40
	i := 2
	for offset := 1; offset < len(bytes); i++ {
		var v int
		v, offset, err = parseBase128Int(bytes, offset)
		if err != nil {
			return
		}
		s[i] = v
	}
	s = s[0:i]
	return
}

func parseRawField(data []byte, msg string) (interface{}, int, error) {
	dumpBytes1(data, fmt.Sprintf("parseRawField: %s", msg), 16)

	switch ASN1BER(data[0]) {
	case Integer:
		length := int(data[1])
		if length == 1 {
			return int(data[2]), 3, nil
		}
		resp, err := parseUint(data[2:(2 + length)])
		return resp, 2 + length, err
	case OctetString:
		length, cursor := parseLength(data)
		return string(data[cursor:length]), length, nil
	case ObjectIdentifier:
		length := int(data[1])
		oid, err := parseObjectIdentifier(data[2 : 2+length])
		return oid, length + 2, err
	default:
		return nil, 0, fmt.Errorf("Unknown field type: %x\n", data[0])
	}
}

func parseUint16(content []byte) int {
	number := uint8(content[1]) | uint8(content[0])<<8
	return int(number)
}

// parseUint64 treats the given bytes as a big-endian, unsigned integer and returns
// the result.
func parseUint64(bytes []byte) (ret uint64, err error) {
	if len(bytes) > 8 {
		// We'll overflow a uint64 in this case.
		err = errors.New("integer too large")
		return
	}
	for bytesRead := 0; bytesRead < len(bytes); bytesRead++ {
		ret <<= 8
		ret |= uint64(bytes[bytesRead])
	}
	return
}

// parseUint treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseUint(bytes []byte) (uint, error) {
	ret64, err := parseUint64(bytes)
	if err != nil {
		return 0, err
	}
	if ret64 != uint64(uint(ret64)) {
		return 0, errors.New("integer too large")
	}
	return uint(ret64), nil
}

//TODO: Figure out if this is still an issue?
// Issue 4389: math/big: add SetUint64 and Uint64 functions to *Int
// uint64ToBigInt copied from: http://github.com/cznic/mathutil/blob/master/mathutil.go#L341
// replace with Uint64ToBigInt or equivalent when using Go 1.1
var uint64ToBigIntDelta big.Int

func init() {
	uint64ToBigIntDelta.SetBit(&uint64ToBigIntDelta, 63, 1)
}

func uint64ToBigInt(n uint64) *big.Int {
	if n <= math.MaxInt64 {
		return big.NewInt(int64(n))
	}

	y := big.NewInt(int64(n - uint64(math.MaxInt64) - 1))
	return y.Add(y, &uint64ToBigIntDelta)
}

// BitStringValue is the structure to use when you want an ASN.1 BIT STRING type. A
// bit string is padded up to the nearest byte in memory and the number of
// valid bits is recorded. Padding bits will be zero.
type BitStringValue struct {
	Bytes     []byte // bits packed into bytes.
	BitLength int    // length in bits.
}

// At returns the bit at the given index. If the index is out of range it
// returns false.
func (b BitStringValue) At(i int) int {
	if i < 0 || i >= b.BitLength {
		return 0
	}
	x := i / 8
	y := 7 - uint(i%8)
	return int(b.Bytes[x]>>y) & 1
}

// RightAlign returns a slice where the padding bits are at the beginning. The
// slice may share memory with the BitString.
func (b BitStringValue) RightAlign() []byte {
	shift := uint(8 - (b.BitLength % 8))
	if shift == 8 || len(b.Bytes) == 0 {
		return b.Bytes
	}

	a := make([]byte, len(b.Bytes))
	a[0] = b.Bytes[0] >> shift
	for i := 1; i < len(b.Bytes); i++ {
		a[i] = b.Bytes[i-1] << (8 - shift)
		a[i] |= b.Bytes[i] >> shift
	}

	return a
}

func (s SNMPVersion) String() string {
	if s == Version1 {
		return "1"
	}
	return "2c"
}

// Partition - returns true when dividing a slice into
// partition_size lengths, including last partition which may be smaller
// than partition_size. This is useful when you have a large array of OIDs
// to run Get() on. See the tests for example usage.
//
// For example for a slice of 8 items to be broken into partitions of
// length 3, Partition returns true for the current_position having
// the following values:
//
// 0  1  2  3  4  5  6  7
//       T        T     T
//
func Partition(curPos, partitionSize, sliceLen int) bool {
	if curPos < 0 || curPos >= sliceLen {
		return false
	}
	if partitionSize == 1 { // redundant, but an obvious optimisation
		return true
	}
	if curPos%partitionSize == partitionSize-1 {
		return true
	}
	if curPos == sliceLen-1 {
		return true
	}
	return false
}

// ToBigInt converts SNMPData.Value to big.Int, or returns a zero big.Int for
// non int-like types (eg strings).
//
// This is a convenience function to make working with SNMPData's easier - it
// reduces the need for type assertions. A big.Int is convenient, as SNMP can
// return int32, uint32, and uint64.
func ToBigInt(value interface{}) *big.Int {
	var val int64
	switch value := value.(type) { // shadow
	case int:
		val = int64(value)
	case int8:
		val = int64(value)
	case int16:
		val = int64(value)
	case int32:
		val = int64(value)
	case int64:
		val = int64(value)
	case uint:
		val = int64(value)
	case uint8:
		val = int64(value)
	case uint16:
		val = int64(value)
	case uint32:
		val = int64(value)
	case uint64:
		return (uint64ToBigInt(value))
	case string:
		// for testing and other apps - numbers may appear as strings
		var err error
		if val, err = strconv.ParseInt(value, 10, 64); err != nil {
			return new(big.Int)
		}
	default:
		return new(big.Int)
	}
	return big.NewInt(val)
}
