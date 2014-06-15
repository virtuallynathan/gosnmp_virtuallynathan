// Copyright 2012 Andreas Louca, 2013 Sonia Hamilton, 2014 Nathan Owens. All rights reserved.  Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

//SNMPVersion indicates the SNMP version
type SNMPVersion uint8

const (
	//Version1 defines the SNMPv1 code
	Version1 SNMPVersion = 0x0
	//Version2c devinces the SNMPv2c code
	Version2c SNMPVersion = 0x1
)

//SNMPPacket contains all of the info required for an SNMP PAcket
type SNMPPacket struct {
	Version      SNMPVersion
	Community    string
	PDUType      PDUType
	RequestID    uint32
	Error        uint8
	ErrorIndex   uint8
	NonRepeaters uint8
	MaxReps      uint8
	Variables    []SNMPData
}

//Variable contains the response???? TODO: Figure out what the heck this means
type Variable struct {
	Name  []int
	Type  ASN1BER
	Value interface{}
}

//VarBind contains bindings to the Variable(s)???? TODO: Figure out what the heck this means
type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

//PDUType indicates the PDU type as defined below
type PDUType byte

const (
	Sequence       PDUType = 0x30
	GetRequest             = 0xa0
	GetNextRequest         = 0xa1
	GetResponse            = 0xa2
	SetRequest             = 0xa3
	Trap                   = 0xa4
	GetBulkRequest         = 0xa5
)

//Logger is an interface used for debugging. Both Print and
//Printf have the same interfaces as Package Log in the std library. The
//Logger interface is small to give you flexibility in how you do
//your debugging.
// For verbose logging to stdout:
//     gosnmp_logger = log.New(os.Stdout, "", 0)
type Logger interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
}

// slog is a global variable that is used for debug logging
var slog Logger

//mashalNeg marshals an SNMP message
func (packet *SNMPPacket) marshalMsg(data []SNMPData,
	pdutype PDUType, requestid uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// version
	buf.Write([]byte{2, 1, byte(packet.Version)})

	// community
	buf.Write([]byte{4, uint8(len(packet.Community))})
	buf.WriteString(packet.Community)

	// pdu
	pdu, err := packet.marshalPDU(data, requestid)
	if err != nil {
		return nil, err
	}
	buf.Write(pdu)

	// build up resulting msg - sequence, length then the tail (buf)
	msg := new(bytes.Buffer)
	msg.WriteByte(byte(Sequence))

	bufLen, err2 := marshalLength(buf.Len())
	if err2 != nil {
		return nil, err2
	}
	msg.Write(bufLen)

	buf.WriteTo(msg) // reverse logic - want to do msg.Write(buf)
	return msg.Bytes(), nil
}

//marshalPDU marshals a PDU
func (packet *SNMPPacket) marshalPDU(data []SNMPData, requestID uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// requestid
	buf.Write([]byte{2, 4})
	err := binary.Write(buf, binary.BigEndian, requestID)
	if err != nil {
		return nil, err
	}

	if packet.PDUType == GetBulkRequest {
		buf.Write([]byte{2, 1, packet.NonRepeaters}) // non repeaters TODO: Wtf does this mean?
		buf.Write([]byte{2, 1, packet.MaxReps})      // max repetitions

	} else { // get and getnext have same packet format
		buf.Write([]byte{2, 1, 0}) // error
		buf.Write([]byte{2, 1, 0}) // error index
	}

	// varbind list
	vbl, err := packet.marshalVBL(data)
	if err != nil {
		return nil, err
	}
	buf.Write(vbl)

	// build up resulting pdu - request type, length, then the tail (buf)
	pdu := new(bytes.Buffer)
	pdu.WriteByte(byte(packet.PDUType))

	bufLen, err2 := marshalLength(buf.Len())
	if err2 != nil {
		return nil, err2
	}
	pdu.Write(bufLen)

	buf.WriteTo(pdu) // reverse logic - want to do pdu.Write(buf)
	return pdu.Bytes(), nil
}

// marshal a varbind list
func (packet *SNMPPacket) marshalVBL(data []SNMPData) ([]byte, error) {

	variableBuf := new(bytes.Buffer)
	for _, pdu := range data {
		vb, err := MarshalVarBind(&pdu)
		if err != nil {
			return nil, err
		}
		variableBuf.Write(vb)
	}

	variableBufBytes := variableBuf.Bytes()
	variableBufLen, err := marshalLength(len(variableBufBytes))
	if err != nil {
		return nil, err
	}

	//FIXME: does bytes.Buffer give better performance than byte slices?
	result := []byte{byte(Sequence)}
	result = append(result, variableBufLen...)
	result = append(result, variableBufBytes...)
	return result, nil
}

//MarshalVarBind marshals a varbind??? TODO: what does this mean?
func MarshalVarBind(data *SNMPData) ([]byte, error) {
	oid, err := marshalOid(data.Name)
	if err != nil {
		return nil, err
	}
	pduBuf := new(bytes.Buffer)
	tmpBuf := new(bytes.Buffer)

	// Marshal the PDU type into the appropriate BER
	switch data.Type {
	case Null:
		pduBuf.Write([]byte{byte(Sequence), byte(len(oid) + 4)})
		pduBuf.Write([]byte{byte(ObjectIdentifier), byte(len(oid))})
		pduBuf.Write(oid)
		pduBuf.Write([]byte{Null, 0x00})
	case Integer:
		// Oid
		tmpBuf.Write([]byte{byte(ObjectIdentifier), byte(len(oid))})
		tmpBuf.Write(oid)
		// Integer
		intBytes := []byte{byte(data.Value.(int))}
		tmpBuf.Write([]byte{byte(Integer), byte(len(intBytes))})
		tmpBuf.Write(intBytes)
		// Sequence, length of oid + integer, then oid/integer data
		pduBuf.WriteByte(byte(Sequence))
		pduBuf.WriteByte(byte(len(oid) + len(intBytes) + 4))
		pduBuf.Write(tmpBuf.Bytes())
	default:
		return nil, fmt.Errorf("Unable to marshal PDU: unknown BER type %d", data.Type)
	}

	return pduBuf.Bytes(), nil
}

// -- Unmarshalling Logic ------------------------------------------------------

func unmarshal(packet []byte) (*SNMPPacket, error) {
	response := new(SNMPPacket)
	response.Variables = make([]SNMPData, 0, 5)

	// Start parsing the packet
	cursor := 0

	// First bytes should be 0x30
	if PDUType(packet[0]) != Sequence {
		return nil, fmt.Errorf("Invalid packet header\n")
	}

	length, cursor := parseLength(packet)
	if len(packet) != length {
		return nil, fmt.Errorf("Error verifying packet sanity: Got %d Expected: %d\n", len(packet), length)
	}
	slog.Printf("Packet sanity verified, we got all the bytes (%d)", length)

	// Parse SNMP Version
	rawVersion, count, err := parseRawField(packet[cursor:], "version")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet version: %s", err.Error())
	}

	cursor += count
	if version, ok := rawVersion.(int); ok {
		response.Version = SNMPVersion(version)
		slog.Printf("Parsed version %d", version)
	}

	// Parse community
	rawCommunity, count, err := parseRawField(packet[cursor:], "community")
	cursor += count
	if community, ok := rawCommunity.(string); ok {
		response.Community = community
		slog.Printf("Parsed community %s", community)
	}

	// Parse SNMP packet type
	requestType := PDUType(packet[cursor])
	switch requestType {
	// known, supported types
	case GetResponse, GetNextRequest, GetBulkRequest:
		response, err = unmarshalResponse(packet[cursor:], response, length, requestType)
		if err != nil {
			return nil, fmt.Errorf("Error in unmarshalResponse: %s", err.Error())
		}
	default:
		return nil, fmt.Errorf("Unknown PDUType %#x", err)
	}
	return response, nil
}

func unmarshalResponse(packet []byte, response *SNMPPacket, length int, requestType PDUType) (*SNMPPacket, error) {
	cursor := 0
	dumpBytes1(packet, "SNMP Packet is GET RESPONSE", 16)
	response.PDUType = requestType

	getResponseLen, cursor := parseLength(packet)
	if len(packet) != getResponseLen {
		return nil, fmt.Errorf("Error verifying Response sanity: Got %d Expected: %d\n", len(packet), getResponseLen)
	}
	slog.Printf("getResponseLen: %d", getResponseLen)

	// Parse requestID
	rawRequestID, count, err := parseRawField(packet[cursor:], "request id")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet request ID: %s", err.Error())
	}
	cursor += count
	if requestid, ok := rawRequestID.(int); ok {
		response.RequestID = uint32(requestid)
		slog.Printf("requestID: %d", response.RequestID)
	}

	if response.PDUType == GetBulkRequest {
		// Parse Non Repeaters
		rawNonRepeaters, count, err := parseRawField(packet[cursor:], "maxReps")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMP packet nonRepeaters: %s", err.Error())
		}
		cursor += count
		if nonRepeaters, ok := rawNonRepeaters.(int); ok {
			response.NonRepeaters = uint8(nonRepeaters)
		}

		// Parse Max Repetitions
		rawMaxReps, count, err := parseRawField(packet[cursor:], "maxReps")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMP packet maxReps: %s", err.Error())
		}
		cursor += count
		if MaxReps, ok := rawMaxReps.(int); ok {
			response.MaxReps = uint8(MaxReps)
		}
	} else {
		// Parse Error-Status
		rawError, count, err := parseRawField(packet[cursor:], "errorStatus")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMP packet error: %s", err.Error())
		}
		cursor += count
		if errorStatus, ok := rawError.(int); ok {
			response.Error = uint8(errorStatus)
			slog.Printf("error-status: %d", uint8(errorStatus))
		}

		// Parse Error-Index
		rawErrorIndex, count, err := parseRawField(packet[cursor:], "error index")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMP packet error index: %s", err.Error())
		}
		cursor += count
		if errorindex, ok := rawErrorIndex.(int); ok {
			response.ErrorIndex = uint8(errorindex)
			slog.Printf("error-index: %d", uint8(errorindex))
		}
	}

	return unmarshalVBL(packet[cursor:], response, length)
}

// unmarshal a Varbind list
func unmarshalVBL(packet []byte, response *SNMPPacket, length int) (*SNMPPacket, error) {

	dumpBytes1(packet, "\n=== unmarshalVBL()", 32)
	var cursor, cursorInc int
	var variableLen int
	if packet[cursor] != 0x30 {
		return nil, fmt.Errorf("Expected a sequence when unmarshalling a VBL, got %x",
			packet[cursor])
	}

	variableLen, cursor = parseLength(packet)
	if len(packet) != variableLen {
		return nil, fmt.Errorf("Error verifying: packet length %d vbl length %d\n",
			len(packet), variableLen)
	}
	slog.Printf("vbl_length: %d", variableLen)

	// Loop & parse Varbinds
	for cursor < variableLen {
		dumpBytes1(packet[cursor:], fmt.Sprintf("\nSTARTING a varbind. Cursor %d", cursor), 32)
		if packet[cursor] != 0x30 {
			return nil, fmt.Errorf("Expected a sequence when unmarshalling a VB, got %x", packet[cursor])
		}

		_, cursorInc = parseLength(packet[cursor:])
		cursor += cursorInc

		// Parse OID
		rawOid, oidLen, err := parseRawField(packet[cursor:], "OID")
		if err != nil {
			return nil, fmt.Errorf("Error parsing OID Value: %s", err.Error())
		}
		cursor += oidLen

		var oid []int
		var ok bool
		if oid, ok = rawOid.([]int); !ok {
			return nil, fmt.Errorf("unable to type assert rawOid |%v| to []int", rawOid)
		}
		slog.Printf("Oid: %s", oidToString(oid))

		// Parse Value
		v, err := decodeValue(packet[cursor:], "value")
		if err != nil {
			return nil, fmt.Errorf("Error decoding value: %v", err)
		}
		valLen, _ := parseLength(packet[cursor:])
		cursor += valLen
		response.Variables = append(response.Variables, SNMPData{oidToString(oid), v.Type, v.Value})
	}
	return response, nil
}

// marshalLength builds a byte representation of length
//
// http://luca.ntop.org/Teaching/Appunti/asn1.html
//
// Length octets. There are two forms: short (for lengths between 0 and 127),
// and long definite (for lengths between 0 and 2^1008 -1).
//
// * Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
// * Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits
//   7-1 give the number of additional length octets. Second and following
//   octets give the length, base 256, most significant digit first.
func marshalLength(length int) ([]byte, error) {

	// more convenient to pass length as int than uint64. Therefore check < 0
	if length < 0 {
		return nil, fmt.Errorf("length must be greater than zero")
	} else if length < 127 {
		return []byte{byte(length)}, nil
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint64(length))
	if err != nil {
		return nil, err
	}

	bufBytes, err2 := buf.ReadBytes(0) // can't use buf.Bytes() - trailing 00's
	if err2 != nil {
		return nil, err
	}
	bufBytes = bufBytes[0 : len(bufBytes)-1] // remove trailing 00

	header := []byte{byte(128 | len(bufBytes))}
	return append(header, bufBytes...), nil
}

func marshalObjectIdentifier(oid []int) (ret []byte, err error) {
	out := new(bytes.Buffer)
	if len(oid) < 2 || oid[0] > 6 || oid[1] >= 40 {
		return nil, errors.New("invalid object identifier")
	}

	err = out.WriteByte(byte(oid[0]*40 + oid[1]))
	if err != nil {
		return
	}
	for i := 2; i < len(oid); i++ {
		err = marshalBase128Int(out, int64(oid[i]))
		if err != nil {
			return
		}
	}

	ret = out.Bytes()
	return
}

func marshalOid(oid string) ([]byte, error) {
	var err error

	// Encode the oid
	oid = strings.Trim(oid, ".")
	oidParts := strings.Split(oid, ".")
	oidBytes := make([]int, len(oidParts))

	// Convert the string OID to an array of integers
	for i := 0; i < len(oidParts); i++ {
		oidBytes[i], err = strconv.Atoi(oidParts[i])
		if err != nil {
			return nil, fmt.Errorf("Unable to parse OID: %s\n", err.Error())
		}
	}

	mOid, err := marshalObjectIdentifier(oidBytes)

	if err != nil {
		return nil, fmt.Errorf("Unable to marshal OID: %s\n", err.Error())
	}

	return mOid, err
}
