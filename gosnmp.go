// Copyright 2012 Andreas Louca, 2013 Sonia Hamilton, 2014 Nathan Owens. All rights reserved.  Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"
)

//MaxOids is the maximum number of oids allowed in a Get()
const MaxOids = 60

//GoSNMP is the struct containing info about an SNMP connection
type GoSNMP struct {
	Target    string        //Target is an IP address
	Port      uint16        //Port is a udp port
	Community string        //Community is an SNMP Community string
	Version   SNMPVersion   //Version is an SNMP Version
	Timeout   time.Duration //Timeout is the timeout for the SNMP Query
	Conn      net.Conn      //Conn is net connection to use, typically establised using GoSNMP.Connect()
	//Logger is the GoSNMP.Logger to use for debugging. If nil, debugging
	//output will be discarded (/dev/null). For verbose logging to stdout:
	//x.Logger = log.New(os.Stdout, "", 0)
	Logger Logger
}

//Default contains the defaul values for an SNMP connection if none are provided
var Default = &GoSNMP{
	Port:      161,
	Community: "public",
	Version:   Version2c,
	Timeout:   time.Duration(2) * time.Second,
}

//SNMPData will be used when doing SNMP Set's
type SNMPData struct {
	Name  string      //Name is an oid in string format eg "1.3.6.1.4.9.27"
	Type  ASN1BER     //The type of the value eg Integer
	Value interface{} // The value to be set by the SNMP set
}

//ASN1BER is a typed byte containing for decoding SNMP
type ASN1BER byte

const (
	EndOfContents     ASN1BER = 0x00
	UnknownType               = 0x00
	Boolean                   = 0x01
	Integer                   = 0x02
	BitString                 = 0x03
	OctetString               = 0x04
	Null                      = 0x05
	ObjectIdentifier          = 0x06
	ObjectDescription         = 0x07
	IPAddress                 = 0x40
	Counter32                 = 0x41
	Gauge32                   = 0x42
	TimeTicks                 = 0x43
	Opaque                    = 0x44
	NsapAddress               = 0x45
	Counter64                 = 0x46
	Uinteger32                = 0x47
	NoSuchObject              = 0x80
	NoSuchInstance            = 0x81
	EndOfMibView              = 0x82
)

//Connect makes an SNMP connection using net.DialTimeout
func (x *GoSNMP) Connect() error {
	Conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", x.Target, x.Port), x.Timeout)
	if err == nil {
		x.Conn = Conn
	} else {
		return fmt.Errorf("Error establishing connection to host: %s\n", err.Error())
	}
	return nil
}

//send is a generic sender.
func (x *GoSNMP) send(pdus []SNMPData, packetOut *SNMPPacket) (result *SNMPPacket, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("recover: %v", e)
		}
	}()

	if x.Conn == nil {
		return nil, fmt.Errorf("&GoSNMP.Conn is missing. Provide a connection or use Connect()")
	}
	x.Conn.SetDeadline(time.Now().Add(x.Timeout))

	if x.Logger == nil {
		x.Logger = log.New(ioutil.Discard, "", 0)
	}
	slog = x.Logger // global variable for debug logging

	// RequestID is only used during tests, therefore use an arbitrary uint32 ie 1
	// FIXME: Should be an atomic counter (started at a random value)
	fBuf, err := packetOut.marshalMsg(pdus, packetOut.PDUType, 1)
	if err != nil {
		return nil, fmt.Errorf("marshal: %v", err)
	}
	_, err = x.Conn.Write(fBuf)
	if err != nil {
		return nil, fmt.Errorf("Error writing to socket: %s", err.Error())
	}

	// Read and unmarshal the response
	resp := make([]byte, 4096, 4096)
	n, err := x.Conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("Error reading from UDP: %s", err.Error())
	}

	packetIn, err := unmarshal(resp[:n])
	if err != nil {
		return nil, fmt.Errorf("Unable to decode packet: %s", err.Error())
	}
	if packetIn == nil {
		return nil, fmt.Errorf("Unable to decode packet: nil")
	}
	if len(packetIn.Variables) < 1 {
		return nil, fmt.Errorf("No response received.")
	}

	// FIXME: We should check that our request id matches, and if it fails
	// jump back up to our read gain (i.e. handle late arriving 'dropped' packet)
	//if packetIn.RequestID != requestID {
	//	Try again!
	//}

	return packetIn, nil
}

//Get send an SNMP GET request using the connection made with Connect
func (x *GoSNMP) Get(oids []string) (result *SNMPPacket, err error) {
	oidCount := len(oids)
	if oidCount > MaxOids {
		return nil, fmt.Errorf("oid count (%d) is greater than MAX_OIDS (%d)",
			oidCount, MaxOids)
	}
	// convert oids slice to data slice
	var data []SNMPData
	for _, oid := range oids {
		data = append(data, SNMPData{oid, Null, nil})
	}
	// build up SnmpPacket
	packetOut := &SNMPPacket{
		Community:  x.Community,
		Error:      0,
		ErrorIndex: 0,
		PDUType:    GetRequest,
		Version:    x.Version,
	}
	return x.send(data, packetOut)
}

//Set send an SNMP SET request using the connection made with Connect
func (x *GoSNMP) Set(data []SNMPData) (result *SNMPPacket, err error) {
	if len(data) != 1 {
		return nil, fmt.Errorf("gosnmp currently only supports SNMP SETs for one oid")
	}
	if data[0].Type != Integer {
		return nil, fmt.Errorf("gosnmp currently only supports SNMP SETs for Integers")
	}
	// build up SNMPPacket
	packetOut := &SNMPPacket{
		Community:  x.Community,
		Error:      0,
		ErrorIndex: 0,
		PDUType:    SetRequest,
		Version:    x.Version,
	}
	return x.send(data, packetOut)
}

//GetNext send an SNMP GETNEXT request using the connection made with Connect
func (x *GoSNMP) GetNext(oids []string) (result *SNMPPacket, err error) {
	oidCount := len(oids)
	if oidCount > MaxOids {
		return nil, fmt.Errorf("oid count (%d) is greater than MAX_OIDS (%d)",
			oidCount, MaxOids)
	}

	// convert oids slice to data slice
	var data []SNMPData
	for _, oid := range oids {
		data = append(data, SNMPData{oid, Null, nil})
	}

	// Marshal and send the packet
	packetOut := &SNMPPacket{
		Community:  x.Community,
		Error:      0,
		ErrorIndex: 0,
		PDUType:    GetNextRequest,
		Version:    x.Version,
	}

	return x.send(data, packetOut)
}

//GetBulk send an SNMP GETBULK request
func (x *GoSNMP) GetBulk(oids []string, nonRepeaters uint8, maxReps uint8) (result *SNMPPacket, err error) {
	oidCount := len(oids)
	if oidCount > MaxOids {
		return nil, fmt.Errorf("oid count (%d) is greater than MAX_OIDS (%d)",
			oidCount, MaxOids)
	}

	// convert oids slice to data slice
	var data []SNMPData
	for _, oid := range oids {
		data = append(data, SNMPData{oid, Null, nil})
	}

	// Marshal and send the packet
	packetOut := &SNMPPacket{
		Community:    x.Community,
		PDUType:      GetBulkRequest,
		Version:      x.Version,
		NonRepeaters: nonRepeaters,
		MaxReps:      maxReps,
	}
	return x.send(data, packetOut)
}
