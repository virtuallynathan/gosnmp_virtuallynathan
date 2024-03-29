// Copyright 2013 Sonia Hamilton, 2014 Nathan Owens All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package gosnmp

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var _ = fmt.Sprintf("dummy") // dummy
var _ = ioutil.Discard       // dummy
var _ = os.DevNull           // dummy

// "Enmarshal" not "Marshal" - easier to select tests via a regex
type testsEnmarshalVarBindPos struct {
	oid string
	// start and finish position of bytes are calculated with application layer
	// starting at byte 0. The easiest way to calculate these values is to use
	// ghex (or similar) to delete the bytes from the lower layers of the
	// capture. Then open the capture in wireshark, right-click, "decode as..."
	// and choose snmp. Click on each varbind and the "packet bytes" window
	// will highlight the corresponding bytes, then the "eyeball tool" can be
	// used to find the start and finish values...
	start   int
	finish  int
	pduType ASN1BER
	pduVal  interface{}
}

type testsEnmarshalT struct {
	version     SNMPVersion
	community   string
	requestType PDUType
	requestID   uint32
	goodBytes   func() []byte              // function and function name returning bytes from tcpdump
	funcName    string                     // could do this via reflection
	pduStart    int                        // start position of the pdu
	vblStart    int                        // start position of the vbl
	finish      int                        // finish position of pdu, vbl and message - all the same
	vbPos       []testsEnmarshalVarBindPos // a slice of positions containing start and finish of each varbind

}

var BenchmarkEnmarshal = []testsEnmarshalT{
	{
		Version2c,
		"public",
		GetRequest,
		1871507044,
		kyoceraReqBytes,
		"kyoceraReq",
		0x0e, // pdu start
		0x1d, // vbl start
		0xa0, // finish
		[]testsEnmarshalVarBindPos{
			{".1.3.6.1.2.1.1.7.0", 0x20, 0x2d, Null, nil},
			{".1.3.6.1.2.1.2.2.1.10.1", 0x2e, 0x3d, Null, nil},
			{".1.3.6.1.2.1.2.2.1.5.1", 0x3e, 0x4d, Null, nil},
			{".1.3.6.1.2.1.1.4.0", 0x4e, 0x5b, Null, nil},
			{".1.3.6.1.2.1.43.5.1.1.15.1", 0x5c, 0x6c, Null, nil},
			{".1.3.6.1.2.1.4.21.1.1.127.0.0.1", 0x6d, 0x7f, Null, nil},
			{".1.3.6.1.4.1.23.2.5.1.1.1.4.2", 0x80, 0x92, Null, nil},
			{".1.3.6.1.2.1.1.3.0", 0x93, 0xa0, Null, nil},
		},
	},
}

var BenchmarkUnmarshalStruct = []struct {
	in  func() []byte
	out *SNMPPacket
}{
	{kyoceraRespBytes,
		&SNMPPacket{
			Version:    Version2c,
			Community:  "public",
			PDUType:    GetResponse,
			RequestID:  1066889284,
			Error:      0,
			ErrorIndex: 0,
			Variables: []SNMPData{
				{
					Name:  ".1.3.6.1.2.1.1.7.0",
					Type:  Integer,
					Value: 104,
				},
				{
					Name:  ".1.3.6.1.2.1.2.2.1.10.1",
					Type:  Counter32,
					Value: 271070065,
				},
				{
					Name:  ".1.3.6.1.2.1.2.2.1.5.1",
					Type:  Gauge32,
					Value: 100000000,
				},
				{
					Name:  ".1.3.6.1.2.1.1.4.0",
					Type:  OctetString,
					Value: "Administrator",
				},
				{
					Name:  ".1.3.6.1.2.1.43.5.1.1.15.1",
					Type:  Null,
					Value: nil,
				},
				{
					Name:  ".1.3.6.1.2.1.4.21.1.1.127.0.0.1",
					Type:  IPAddress,
					Value: "127.0.0.1",
				},
				{
					Name:  ".1.3.6.1.4.1.23.2.5.1.1.1.4.2",
					Type:  OctetString,
					Value: "00 15 99 37 76 2b",
				},
				{
					Name:  ".1.3.6.1.2.1.1.3.0",
					Type:  TimeTicks,
					Value: 318870100,
				},
			},
		},
	},
}

var testsEnmarshal = []testsEnmarshalT{
	{
		Version2c,
		"public",
		GetRequest,
		1871507044,
		kyoceraReqBytes,
		"kyoceraReq",
		0x0e, // pdu start
		0x1d, // vbl start
		0xa0, // finish
		[]testsEnmarshalVarBindPos{
			{".1.3.6.1.2.1.1.7.0", 0x20, 0x2d, Null, nil},
			{".1.3.6.1.2.1.2.2.1.10.1", 0x2e, 0x3d, Null, nil},
			{".1.3.6.1.2.1.2.2.1.5.1", 0x3e, 0x4d, Null, nil},
			{".1.3.6.1.2.1.1.4.0", 0x4e, 0x5b, Null, nil},
			{".1.3.6.1.2.1.43.5.1.1.15.1", 0x5c, 0x6c, Null, nil},
			{".1.3.6.1.2.1.4.21.1.1.127.0.0.1", 0x6d, 0x7f, Null, nil},
			{".1.3.6.1.4.1.23.2.5.1.1.1.4.2", 0x80, 0x92, Null, nil},
			{".1.3.6.1.2.1.1.3.0", 0x93, 0xa0, Null, nil},
		},
	},
	{
		Version1,
		"privatelab",
		SetRequest,
		526895288,
		portOnOutgoing1,
		"portOnOutgoing1",
		0x11, // pdu start
		0x1f, // vbl start
		0x36, // finish
		[]testsEnmarshalVarBindPos{
			{".1.3.6.1.4.1.318.1.1.4.4.2.1.3.5", 0x21, 0x36, Integer, 1},
		},
	},
	{
		Version1,
		"privatelab",
		SetRequest,
		1826072803,
		portOffOutgoing1,
		"portOffOutgoing1",
		0x11, // pdu start
		0x1f, // vbl start
		0x36, // finish
		[]testsEnmarshalVarBindPos{
			{".1.3.6.1.4.1.318.1.1.4.4.2.1.3.5", 0x21, 0x36, Integer, 2},
		},
	},
}

//Benchmarks
func BenchmarkMarshalMsg(b *testing.B) {
	//run the MarshalMsg function b.N times
	for n := 0; n < b.N; n++ {
		test := testsEnmarshal[0]
		x := &SNMPPacket{
			Community: test.community,
			Version:   test.version,
			PDUType:   test.requestType,
			RequestID: test.requestID,
		}
		data := vbPosPDUs(test)

		_, err := x.marshalMsg(data, test.requestType, test.requestID)
		if err != nil {
			b.Errorf("#%s: marshal() err returned: %v", test.funcName, err)
		}
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	//run the MarshalMsg function b.N times
	for n := 0; n < b.N; n++ {
		for _, test := range testsUnmarshal {
			if _, err := unmarshal(test.in()); err != nil {
				b.Errorf("Unmarshal returned err: %v", err)
			}
		}
	}

}

//Tests
// vbPosPDUs returns a slice of oids in the given test
func vbPosPDUs(test testsEnmarshalT) (data []SNMPData) {
	for _, vbp := range test.vbPos {
		pdu := SNMPData{vbp.oid, vbp.pduType, vbp.pduVal}
		data = append(data, pdu)
	}
	return
}

// check_byte_equality walks the bytes in test_bytes, and compares them to good_bytes
func checkByteEq(t *testing.T, test testsEnmarshalT, testBytes []byte, start int, finish int) {
	testBytesLen := len(testBytes)

	goodBytes := test.goodBytes()
	goodBytes = goodBytes[start : finish+1]
	for cursor := range goodBytes {
		if testBytesLen < cursor {
			t.Errorf("%s: test_bytes_len (%d) < cursor (%d)", test.funcName, testBytesLen, cursor)
			break
		}
		if testBytes[cursor] != goodBytes[cursor] {
			t.Errorf("%s: cursor %d: test_bytes != good_bytes:\n%s\n%s",
				test.funcName,
				cursor,
				dumpBytes2("good", goodBytes, cursor),
				dumpBytes2("test", testBytes, cursor))
			break
		}
	}
}

// Enmarshal tests in order that should be used for troubleshooting
// ie check each varbind is working, then the varbind list, etc
func TestEnmarshalVarBind(t *testing.T) {
	// slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

	for _, test := range testsEnmarshal {
		for j, test2 := range test.vbPos {
			snmppdu := &SNMPData{test2.oid, test2.pduType, test2.pduVal}
			testBytes, err := MarshalVarBind(snmppdu)
			if err != nil {
				t.Errorf("#%s:%d:%s err returned: %v",
					test.funcName, j, test2.oid, err)
			}

			checkByteEq(t, test, testBytes, test2.start, test2.finish)
		}
	}
}

func TestEnmarshalVBL(t *testing.T) {
	// slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

	for _, test := range testsEnmarshal {
		x := &SNMPPacket{
			Community: test.community,
			Version:   test.version,
			RequestID: test.requestID,
		}

		data := vbPosPDUs(test)

		testBytes, err := x.marshalVBL(data)
		if err != nil {
			t.Errorf("#%s: marshalVBL() err returned: %v", test.funcName, err)
		}

		checkByteEq(t, test, testBytes, test.vblStart, test.finish)
	}
}

func TestEnmarshalPDU(t *testing.T) {
	// slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

	for _, test := range testsEnmarshal {
		x := &SNMPPacket{
			Community: test.community,
			Version:   test.version,
			PDUType:   test.requestType,
			RequestID: test.requestID,
		}
		data := vbPosPDUs(test)

		testBytes, err := x.marshalPDU(data, test.requestID)
		if err != nil {
			t.Errorf("#%s: marshalPDU() err returned: %v", test.funcName, err)
		}

		checkByteEq(t, test, testBytes, test.pduStart, test.finish)
	}
}

func TestEnmarshalMsg(t *testing.T) {
	// slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

	for _, test := range testsEnmarshal {
		x := &SNMPPacket{
			Community: test.community,
			Version:   test.version,
			PDUType:   test.requestType,
			RequestID: test.requestID,
		}
		data := vbPosPDUs(test)

		testBytes, err := x.marshalMsg(data, test.requestType, test.requestID)
		if err != nil {
			t.Errorf("#%s: marshal() err returned: %v", test.funcName, err)
		}
		checkByteEq(t, test, testBytes, 0, test.finish)
	}
}

// -- Unmarshal -----------------------------------------------------------------

var testsUnmarshal = []struct {
	in  func() []byte
	out *SNMPPacket
}{
	{kyoceraRespBytes,
		&SNMPPacket{
			Version:    Version2c,
			Community:  "public",
			PDUType:    GetResponse,
			RequestID:  1066889284,
			Error:      0,
			ErrorIndex: 0,
			Variables: []SNMPData{
				{
					Name:  ".1.3.6.1.2.1.1.7.0",
					Type:  Integer,
					Value: 104,
				},
				{
					Name:  ".1.3.6.1.2.1.2.2.1.10.1",
					Type:  Counter32,
					Value: 271070065,
				},
				{
					Name:  ".1.3.6.1.2.1.2.2.1.5.1",
					Type:  Gauge32,
					Value: 100000000,
				},
				{
					Name:  ".1.3.6.1.2.1.1.4.0",
					Type:  OctetString,
					Value: "Administrator",
				},
				{
					Name:  ".1.3.6.1.2.1.43.5.1.1.15.1",
					Type:  Null,
					Value: nil,
				},
				{
					Name:  ".1.3.6.1.2.1.4.21.1.1.127.0.0.1",
					Type:  IPAddress,
					Value: "127.0.0.1",
				},
				{
					Name:  ".1.3.6.1.4.1.23.2.5.1.1.1.4.2",
					Type:  OctetString,
					Value: "00 15 99 37 76 2b",
				},
				{
					Name:  ".1.3.6.1.2.1.1.3.0",
					Type:  TimeTicks,
					Value: 318870100,
				},
			},
		},
	},
	{ciscoRespBytes,
		&SNMPPacket{
			Version:    Version2c,
			Community:  "public",
			PDUType:    GetResponse,
			RequestID:  4876669,
			Error:      0,
			ErrorIndex: 0,
			Variables: []SNMPData{
				{
					Name:  ".1.3.6.1.2.1.1.7.0",
					Type:  Integer,
					Value: 78,
				},
				{
					Name:  ".1.3.6.1.2.1.2.2.1.2.6",
					Type:  OctetString,
					Value: "GigabitEthernet0",
				},
				{
					Name:  ".1.3.6.1.2.1.2.2.1.5.3",
					Type:  Gauge32,
					Value: uint(4294967295),
				},
				{
					Name:  ".1.3.6.1.2.1.2.2.1.7.2",
					Type:  NoSuchInstance,
					Value: nil,
				},
				{
					Name:  ".1.3.6.1.2.1.2.2.1.9.3",
					Type:  TimeTicks,
					Value: 2970,
				},
				{
					Name:  ".1.3.6.1.2.1.3.1.1.2.10.1.10.11.0.17",
					Type:  OctetString,
					Value: "00 07 7d 4d 09 00",
				},
				{
					Name:  ".1.3.6.1.2.1.3.1.1.3.10.1.10.11.0.2",
					Type:  IPAddress,
					Value: "10.11.0.2",
				},
				{
					Name:  ".1.3.6.1.2.1.4.20.1.1.110.143.197.1",
					Type:  IPAddress,
					Value: "110.143.197.1",
				},
				{
					Name:  ".1.3.6.1.66.1",
					Type:  NoSuchObject,
					Value: nil,
				},
				{
					Name:  ".1.3.6.1.2.1.1.2.0",
					Type:  ObjectIdentifier,
					Value: ".1.3.6.1.4.1.9.1.1166",
				},
			},
		},
	},
	{portOnIncoming1,
		&SNMPPacket{
			Version:    Version1,
			Community:  "privatelab",
			PDUType:    GetResponse,
			RequestID:  526895288,
			Error:      0,
			ErrorIndex: 0,
			Variables: []SNMPData{
				{
					Name:  ".1.3.6.1.4.1.318.1.1.4.4.2.1.3.5",
					Type:  Integer,
					Value: 1,
				},
			},
		},
	},
	{portOffIncoming1,
		&SNMPPacket{
			Version:    Version1,
			Community:  "privatelab",
			PDUType:    GetResponse,
			RequestID:  1826072803,
			Error:      0,
			ErrorIndex: 0,
			Variables: []SNMPData{
				{
					Name:  ".1.3.6.1.4.1.318.1.1.4.4.2.1.3.5",
					Type:  Integer,
					Value: 2,
				},
			},
		},
	},
	{ciscoGetNextRespBytes,
		&SNMPPacket{
			Version:    Version2c,
			Community:  "public",
			PDUType:    GetResponse,
			RequestID:  1528674030,
			Error:      0,
			ErrorIndex: 0,
			Variables: []SNMPData{
				{
					Name:  ".1.3.6.1.2.1.3.1.1.3.2.1.192.168.104.2",
					Type:  IPAddress,
					Value: "192.168.104.2",
				},
				{
					Name:  ".1.3.6.1.2.1.92.1.2.1.0",
					Type:  Counter32,
					Value: 0,
				},
				{
					Name:  ".1.3.6.1.2.1.1.9.1.3.3",
					Type:  OctetString,
					Value: "The MIB module for managing IP and ICMP implementations",
				},
				{
					Name:  ".1.3.6.1.2.1.1.9.1.4.2",
					Type:  TimeTicks,
					Value: 21,
				},
				{
					Name:  ".1.3.6.1.2.1.2.1.0",
					Type:  Integer,
					Value: 3,
				},
				{
					Name:  ".1.3.6.1.2.1.1.2.0",
					Type:  ObjectIdentifier,
					Value: ".1.3.6.1.4.1.8072.3.2.10",
				},
			},
		},
	},
	{ciscoGetBulkRespBytes,
		&SNMPPacket{
			Version:      Version2c,
			Community:    "public",
			PDUType:      GetResponse,
			RequestID:    250000266,
			NonRepeaters: 0,
			MaxReps:      10,
			Variables: []SNMPData{
				{
					Name:  ".1.3.6.1.2.1.1.9.1.4.1",
					Type:  TimeTicks,
					Value: 21,
				},
				{
					Name:  ".1.3.6.1.2.1.1.9.1.4.2",
					Type:  TimeTicks,
					Value: 21,
				},
				{
					Name:  ".1.3.6.1.2.1.1.9.1.4.3",
					Type:  TimeTicks,
					Value: 21,
				},
				{
					Name:  ".1.3.6.1.2.1.1.9.1.4.4",
					Type:  TimeTicks,
					Value: 21,
				},
				{
					Name:  ".1.3.6.1.2.1.1.9.1.4.5",
					Type:  TimeTicks,
					Value: 21,
				},
				{
					Name:  ".1.3.6.1.2.1.1.9.1.4.6",
					Type:  TimeTicks,
					Value: 23,
				},
				{
					Name:  ".1.3.6.1.2.1.1.9.1.4.7",
					Type:  TimeTicks,
					Value: 23,
				},
				{
					Name:  ".1.3.6.1.2.1.1.9.1.4.8",
					Type:  TimeTicks,
					Value: 23,
				},
				{
					Name:  ".1.3.6.1.2.1.2.1.0",
					Type:  Integer,
					Value: 3,
				},
				{
					Name:  ".1.3.6.1.2.1.2.2.1.1.1",
					Type:  Integer,
					Value: 1,
				},
			},
		},
	},
}

func TestUnmarshal(t *testing.T) {

	//slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

SANITY:
	for i, test := range testsUnmarshal {
		var err error
		var res *SNMPPacket

		if res, err = unmarshal(test.in()); err != nil {
			t.Errorf("#%d, Unmarshal returned err: %v", i, err)
			continue SANITY
		} else if res == nil {
			t.Errorf("#%d, Unmarshal returned nil", i)
			continue SANITY
		}

		// test "header" fields
		if res.Version != test.out.Version {
			t.Errorf("#%d Version result: %v, test: %v", i, res.Version, test.out.Version)
		}
		if res.Community != test.out.Community {
			t.Errorf("#%d Community result: %v, test: %v", i, res.Community, test.out.Community)
		}
		if res.PDUType != test.out.PDUType {
			t.Errorf("#%d PDUType result: %v, test: %v", i, res.PDUType, test.out.PDUType)
		}
		if res.RequestID != test.out.RequestID {
			t.Errorf("#%d RequestID result: %v, test: %v", i, res.RequestID, test.out.RequestID)
		}
		if res.Error != test.out.Error {
			t.Errorf("#%d Error result: %v, test: %v", i, res.Error, test.out.Error)
		}
		if res.ErrorIndex != test.out.ErrorIndex {
			t.Errorf("#%d ErrorIndex result: %v, test: %v", i, res.ErrorIndex, test.out.ErrorIndex)
		}

		// test varbind values
		for n, vb := range test.out.Variables {
			if len(res.Variables) < n {
				t.Errorf("#%d:%d ran out of varbind results", i, n)
				continue SANITY
			}
			vbr := res.Variables[n]

			if vbr.Name != vb.Name {
				t.Errorf("#%d:%d Name result: %v, test: %v", i, n, vbr.Name, vb.Name)
			}
			if vbr.Type != vb.Type {
				t.Errorf("#%d:%d Type result: %v, test: %v", i, n, vbr.Type, vb.Type)
			}

			switch vb.Type {
			case Integer, Gauge32, Counter32, TimeTicks, Counter64:
				vbval := ToBigInt(vb.Value)
				vbrval := ToBigInt(vbr.Value)
				if vbval.Cmp(vbrval) != 0 {
					t.Errorf("#%d:%d Value result: %v, test: %v", i, n, vbr.Value, vb.Value)
				}
			case OctetString, IPAddress, ObjectIdentifier:
				if vb.Value != vbr.Value {
					t.Errorf("#%d:%d Value result: %v, test: %v", i, n, vbr.Value, vb.Value)
				}
			case Null, NoSuchObject, NoSuchInstance:
				if (vb.Value != nil) || (vbr.Value != nil) {
					t.Errorf("#%d:%d Value result: %v, test: %v", i, n, vbr.Value, vb.Value)
				}
			default:
				t.Errorf("#%d:%d Unhandled case result: %v, test: %v", i, n, vbr.Value, vb.Value)
			}

		}
	}
}

// -----------------------------------------------------------------------------
/*
* byte dumps generated using tcpdump and github.com/jteeuwen/go-bindata eg
  `sudo tcpdump -s 0 -i eth0 -w cisco.pcap host 203.50.251.17 and port 161`
* Frame, Ethernet II, IP and UDP layers removed from generated bytes
*/
/*
kyoceraRespBytes corresponds to the response section of this snmpget
Simple Network Management Protocol
  version: v2c (1)
  community: public
  data: get-response (2)
    get-response
      request-id: 1066889284
      error-status: noError (0)
      error-index: 0
      variable-bindings: 8 items
        1.3.6.1.2.1.1.7.0: 104
        1.3.6.1.2.1.2.2.1.10.1: 271070065
        1.3.6.1.2.1.2.2.1.5.1: 100000000
        1.3.6.1.2.1.1.4.0: 41646d696e6973747261746f72
        1.3.6.1.2.1.43.5.1.1.15.1: Value (Null)
        1.3.6.1.2.1.4.21.1.1.127.0.0.1: 127.0.0.1 (127.0.0.1)
        1.3.6.1.4.1.23.2.5.1.1.1.4.2: 00159937762b
        1.3.6.1.2.1.1.3.0: 318870100
*/

func kyoceraRespBytes() []byte {
	return []byte{
		0x30, 0x81, 0xc2, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c,
		0x69, 0x63, 0xa2, 0x81, 0xb4, 0x02, 0x04, 0x3f, 0x97, 0x70, 0x44, 0x02,
		0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x81, 0xa5, 0x30, 0x0d, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00, 0x02, 0x01, 0x68, 0x30,
		0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0a,
		0x01, 0x41, 0x04, 0x10, 0x28, 0x33, 0x71, 0x30, 0x12, 0x06, 0x0a, 0x2b,
		0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x05, 0x01, 0x42, 0x04, 0x05,
		0xf5, 0xe1, 0x00, 0x30, 0x19, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x04, 0x00, 0x04, 0x0d, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73,
		0x74, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x30, 0x0f, 0x06, 0x0b, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x2b, 0x05, 0x01, 0x01, 0x0f, 0x01, 0x05, 0x00, 0x30,
		0x15, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x04, 0x15, 0x01, 0x01,
		0x7f, 0x00, 0x00, 0x01, 0x40, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x30, 0x17,
		0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x17, 0x02, 0x05, 0x01, 0x01,
		0x01, 0x04, 0x02, 0x04, 0x06, 0x00, 0x15, 0x99, 0x37, 0x76, 0x2b, 0x30,
		0x10, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43,
		0x04, 0x13, 0x01, 0x92, 0x54,
	}
}

/*
ciscoRespBytes corresponds to the response section of this snmpget:
% snmpget -On -v2c -c public 203.50.251.17 1.3.6.1.2.1.1.7.0 1.3.6.1.2.1.2.2.1.2.6 1.3.6.1.2.1.2.2.1.5.3 1.3.6.1.2.1.2.2.1.7.2 1.3.6.1.2.1.2.2.1.9.3 1.3.6.1.2.1.3.1.1.2.10.1.10.11.0.17 1.3.6.1.2.1.3.1.1.3.10.1.10.11.0.2 1.3.6.1.2.1.4.20.1.1.110.143.197.1 1.3.6.1.66.1 1.3.6.1.2.1.1.2.0
.1.3.6.1.2.1.1.7.0 = INTEGER: 78
.1.3.6.1.2.1.2.2.1.2.6 = STRING: GigabitEthernet0
.1.3.6.1.2.1.2.2.1.5.3 = Gauge32: 4294967295
.1.3.6.1.2.1.2.2.1.7.2 = No Such Instance currently exists at this OID
.1.3.6.1.2.1.2.2.1.9.3 = Timeticks: (2970) 0:00:29.70
.1.3.6.1.2.1.3.1.1.2.10.1.10.11.0.17 = Hex-STRING: 00 07 7D 4D 09 00
.1.3.6.1.2.1.3.1.1.3.10.1.10.11.0.2 = Network Address: 0A:0B:00:02
.1.3.6.1.2.1.4.20.1.1.110.143.197.1 = IpAddress: 110.143.197.1
.1.3.6.1.66.1 = No Such Object available on this agent at this OID
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.9.1.1166
*/

func ciscoRespBytes() []byte {
	return []byte{
		0x30, 0x81,
		0xf1, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
		0xa2, 0x81, 0xe3, 0x02, 0x03, 0x4a, 0x69, 0x7d, 0x02, 0x01, 0x00, 0x02,
		0x01, 0x00, 0x30, 0x81, 0xd5, 0x30, 0x0d, 0x06, 0x08, 0x2b, 0x06, 0x01,
		0x02, 0x01, 0x01, 0x07, 0x00, 0x02, 0x01, 0x4e, 0x30, 0x1e, 0x06, 0x0a,
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x06, 0x04, 0x10,
		0x47, 0x69, 0x67, 0x61, 0x62, 0x69, 0x74, 0x45, 0x74, 0x68, 0x65, 0x72,
		0x6e, 0x65, 0x74, 0x30, 0x30, 0x13, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x02, 0x02, 0x01, 0x05, 0x03, 0x42, 0x05, 0x00, 0xff, 0xff, 0xff,
		0xff, 0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02,
		0x01, 0x07, 0x02, 0x81, 0x00, 0x30, 0x10, 0x06, 0x0a, 0x2b, 0x06, 0x01,
		0x02, 0x01, 0x02, 0x02, 0x01, 0x09, 0x03, 0x43, 0x02, 0x0b, 0x9a, 0x30,
		0x19, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x03, 0x01, 0x01, 0x02,
		0x0a, 0x01, 0x0a, 0x0b, 0x00, 0x11, 0x04, 0x06, 0x00, 0x07, 0x7d, 0x4d,
		0x09, 0x00, 0x30, 0x17, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x03,
		0x01, 0x01, 0x03, 0x0a, 0x01, 0x0a, 0x0b, 0x00, 0x02, 0x40, 0x04, 0x0a,
		0x0b, 0x00, 0x02, 0x30, 0x17, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x04, 0x14, 0x01, 0x01, 0x6e, 0x81, 0x0f, 0x81, 0x45, 0x01, 0x40, 0x04,
		0x6e, 0x8f, 0xc5, 0x01, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x42,
		0x01, 0x80, 0x00, 0x30, 0x15, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x02, 0x00, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x09, 0x01,
		0x89, 0x0e,
	}
}

/*
kyoceraReqBytes corresponds to the request section of this snmpget:
snmpget -On -v2c -c public 192.168.1.10 1.3.6.1.2.1.1.7.0 1.3.6.1.2.1.2.2.1.10.1 1.3.6.1.2.1.2.2.1.5.1 1.3.6.1.2.1.1.4.0 1.3.6.1.2.1.43.5.1.1.15.1 1.3.6.1.2.1.4.21.1.1.127.0.0.1 1.3.6.1.4.1.23.2.5.1.1.1.4.2 1.3.6.1.2.1.1.3.0
.1.3.6.1.2.1.1.7.0 = INTEGER: 104
.1.3.6.1.2.1.2.2.1.10.1 = Counter32: 144058856
.1.3.6.1.2.1.2.2.1.5.1 = Gauge32: 100000000
.1.3.6.1.2.1.1.4.0 = STRING: "Administrator"
.1.3.6.1.2.1.43.5.1.1.15.1 = NULL
.1.3.6.1.2.1.4.21.1.1.127.0.0.1 = IpAddress: 127.0.0.1
.1.3.6.1.4.1.23.2.5.1.1.1.4.2 = Hex-STRING: 00 15 99 37 76 2B
.1.3.6.1.2.1.1.3.0 = Timeticks: (120394900) 13 days, 22:25:49.00
*/

func kyoceraReqBytes() []byte {
	return []byte{
		0x30, 0x81,
		0x9e, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
		0xa0, 0x81, 0x90, 0x02, 0x04, 0x6f, 0x8c, 0xee, 0x64, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x00, 0x30, 0x81, 0x81, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x01, 0x07, 0x00, 0x05, 0x00, 0x30, 0x0e, 0x06, 0x0a,
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0a, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01,
		0x05, 0x01, 0x05, 0x00, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x04, 0x00, 0x05, 0x00, 0x30, 0x0f, 0x06, 0x0b, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x2b, 0x05, 0x01, 0x01, 0x0f, 0x01, 0x05, 0x00, 0x30,
		0x11, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x04, 0x15, 0x01, 0x01,
		0x7f, 0x00, 0x00, 0x01, 0x05, 0x00, 0x30, 0x11, 0x06, 0x0d, 0x2b, 0x06,
		0x01, 0x04, 0x01, 0x17, 0x02, 0x05, 0x01, 0x01, 0x01, 0x04, 0x02, 0x05,
		0x00, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03,
		0x00, 0x05, 0x00,
	}
}

// === snmpset dumps ===
/*
portOn*1() correspond to this snmpset and response:
snmpset -v 1 -c privatelab 192.168.100.124 .1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 i 1
Simple Network Management Protocol
  version: version-1 (0)
  community: privatelab
  data: set-request (3)
    set-request
      request-id: 526895288
      error-status: noError (0)
      error-index: 0
      variable-bindings: 1 item
        1.3.6.1.4.1.318.1.1.4.4.2.1.3.5:
          Object Name: 1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 (iso.3.6.1.4.1.318.1.1.4.4.2.1.3.5)
          Value (Integer32): 1

Simple Network Management Protocol
  version: version-1 (0)
  community: privatelab
  data: get-response (2)
    get-response
      request-id: 526895288
      error-status: noError (0)
      error-index: 0
      variable-bindings: 1 item
        1.3.6.1.4.1.318.1.1.4.4.2.1.3.5:
          Object Name: 1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 (iso.3.6.1.4.1.318.1.1.4.4.2.1.3.5)
          Value (Integer32): 1
*/

func portOnOutgoing1() []byte {
	return []byte{
		0x30, 0x35, 0x02, 0x01, 0x00, 0x04, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61,
		0x74, 0x65, 0x6c, 0x61, 0x62, 0xa3, 0x24, 0x02, 0x04, 0x1f, 0x67, 0xc8,
		0xb8, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30, 0x14, 0x06,
		0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x3e, 0x01, 0x01, 0x04, 0x04,
		0x02, 0x01, 0x03, 0x05, 0x02, 0x01, 0x01,
	}
}

func portOnIncoming1() []byte {
	return []byte{
		0x30, 0x82, 0x00, 0x35, 0x02, 0x01, 0x00, 0x04, 0x0a, 0x70, 0x72, 0x69,
		0x76, 0x61, 0x74, 0x65, 0x6c, 0x61, 0x62, 0xa2, 0x24, 0x02, 0x04, 0x1f,
		0x67, 0xc8, 0xb8, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30,
		0x14, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x3e, 0x01, 0x01,
		0x04, 0x04, 0x02, 0x01, 0x03, 0x05, 0x02, 0x01, 0x01,
	}
}

/*
portOff*1() correspond to this snmpset and response:
snmpset -v 1 -c privatelab 192.168.100.124 .1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 i 2
Simple Network Management Protocol
  version: version-1 (0)
  community: privatelab
  data: set-request (3)
    set-request
      request-id: 1826072803
      error-status: noError (0)
      error-index: 0
      variable-bindings: 1 item
        1.3.6.1.4.1.318.1.1.4.4.2.1.3.5:
          Object Name: 1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 (iso.3.6.1.4.1.318.1.1.4.4.2.1.3.5)
          Value (Integer32): 2

Simple Network Management Protocol
  version: version-1 (0)
  community: privatelab
  data: get-response (2)
    get-response
      request-id: 1826072803
      error-status: noError (0)
      error-index: 0
      variable-bindings: 1 item
        1.3.6.1.4.1.318.1.1.4.4.2.1.3.5:
          Object Name: 1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 (iso.3.6.1.4.1.318.1.1.4.4.2.1.3.5)
          Value (Integer32): 2
*/

func portOffOutgoing1() []byte {
	return []byte{
		0x30, 0x35, 0x02, 0x01, 0x00, 0x04, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61,
		0x74, 0x65, 0x6c, 0x61, 0x62, 0xa3, 0x24, 0x02, 0x04, 0x6c, 0xd7, 0xa8,
		0xe3, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30, 0x14, 0x06,
		0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x3e, 0x01, 0x01, 0x04, 0x04,
		0x02, 0x01, 0x03, 0x05, 0x02, 0x01, 0x02,
	}
}

func portOffIncoming1() []byte {
	return []byte{
		0x30, 0x82, 0x00, 0x35, 0x02, 0x01, 0x00, 0x04, 0x0a, 0x70, 0x72, 0x69,
		0x76, 0x61, 0x74, 0x65, 0x6c, 0x61, 0x62, 0xa2, 0x24, 0x02, 0x04, 0x6c,
		0xd7, 0xa8, 0xe3, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30,
		0x14, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x3e, 0x01, 0x01,
		0x04, 0x04, 0x02, 0x01, 0x03, 0x05, 0x02, 0x01, 0x02,
	}
}

func ciscoGetNextRespBytes() []byte {
	return []byte{
		0x30, 0x81,
		0xc8, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
		0xa2, 0x81, 0xba, 0x02, 0x04, 0x5b, 0x1d, 0xb6, 0xee, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x00, 0x30, 0x81, 0xab, 0x30, 0x19, 0x06, 0x11, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x03, 0x01, 0x01, 0x03, 0x02, 0x01, 0x81, 0x40, 0x81,
		0x28, 0x68, 0x02, 0x40, 0x04, 0xc0, 0xa8, 0x68, 0x02, 0x30, 0x0f, 0x06,
		0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x5c, 0x01, 0x02, 0x01, 0x00, 0x41,
		0x01, 0x00, 0x30, 0x45, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
		0x09, 0x01, 0x03, 0x03, 0x04, 0x37, 0x54, 0x68, 0x65, 0x20, 0x4d, 0x49,
		0x42, 0x20, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x20, 0x66, 0x6f, 0x72,
		0x20, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x69, 0x6e, 0x67, 0x20, 0x49, 0x50,
		0x20, 0x61, 0x6e, 0x64, 0x20, 0x49, 0x43, 0x4d, 0x50, 0x20, 0x69, 0x6d,
		0x70, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
		0x73, 0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09,
		0x01, 0x04, 0x02, 0x43, 0x01, 0x15, 0x30, 0x0d, 0x06, 0x08, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x03, 0x30, 0x16, 0x06,
		0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x0a, 0x2b,
		0x06, 0x01, 0x04, 0x01, 0xbf, 0x08, 0x03, 0x02, 0x0a,
	}
}

func ciscoGetNextReqBytes() []byte {
	return []byte{
		0x30, 0x7e,
		0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa1,
		0x71, 0x02, 0x04, 0x5b, 0x1d, 0xb6, 0xee, 0x02, 0x01, 0x00, 0x02, 0x01,
		0x00, 0x30, 0x63, 0x30, 0x15, 0x06, 0x11, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x03, 0x01, 0x01, 0x03, 0x02, 0x01, 0x81, 0x40, 0x81, 0x28, 0x68, 0x01,
		0x05, 0x00, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x5c,
		0x01, 0x02, 0x05, 0x00, 0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x09, 0x01, 0x03, 0x02, 0x05, 0x00, 0x30, 0x0e, 0x06, 0x0a,
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01,
		0x04, 0x08, 0x05, 0x00, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
	}
}

/* ciscoGetBulk*Bytes corresponds to this snmpbulkget command:
$ snmpbulkget -v2c -cpublic  127.0.0.1:161 1.3.6.1.2.1.1.9.1.3.52
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (21) 0:00:00.21
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (21) 0:00:00.21
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (21) 0:00:00.21
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (21) 0:00:00.21
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (21) 0:00:00.21
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (23) 0:00:00.23
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (23) 0:00:00.23
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (23) 0:00:00.23
iso.3.6.1.2.1.2.1.0 = INTEGER: 3
iso.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1

*/
func ciscoGetBulkReqBytes() []byte {
	return []byte{
		0x30, 0x2b,
		0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa5,
		0x1e, 0x02, 0x04, 0x7d, 0x89, 0x68, 0xda, 0x02, 0x01, 0x00, 0x02, 0x01,
		0x0a, 0x30, 0x10, 0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x09, 0x01, 0x03, 0x34, 0x05, 0x00, 0x00,
	}
}

func ciscoGetBulkRespBytes() []byte {
	return []byte{
		0x30, 0x81,
		0xc5, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
		0xa2, 0x81, 0xb7, 0x02, 0x04, 0x0e, 0xe6, 0xb3, 0x8a, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x00, 0x30, 0x81, 0xa8, 0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x01, 0x43, 0x01, 0x15, 0x30,
		0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04,
		0x02, 0x43, 0x01, 0x15, 0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x09, 0x01, 0x04, 0x03, 0x43, 0x01, 0x15, 0x30, 0x0f, 0x06,
		0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x04, 0x43,
		0x01, 0x15, 0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
		0x09, 0x01, 0x04, 0x05, 0x43, 0x01, 0x15, 0x30, 0x0f, 0x06, 0x0a, 0x2b,
		0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x06, 0x43, 0x01, 0x17,
		0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01,
		0x04, 0x07, 0x43, 0x01, 0x17, 0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01,
		0x02, 0x01, 0x01, 0x09, 0x01, 0x04, 0x08, 0x43, 0x01, 0x17, 0x30, 0x0d,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01,
		0x03, 0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02,
		0x01, 0x01, 0x01, 0x02, 0x01, 0x01,
	}
}
