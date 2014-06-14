// Copyright 2013 Sonia Hamilton. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package gosnmp

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type testResults map[string]SNMPData

var veraxDevices = []struct {
	path string
	port uint16
}{
	{"device/os/os-linux-std.txt", 161},
	{"device/cisco/cisco_router.txt", 162},
}

// 1 <= PartitonSize <= MaxOids - adjust as required
const PartitonSize = 3

// reduce oidCount to speed up tests;
// set to 1<<32 - 1 (MaxUint32) for everything
const OidCount = 1<<16 - 1

func TestVeraxGet(t *testing.T) {
	for i, test := range veraxDevices {
		var err error

		// load verax results
		var vResults testResults
		if vResults, err = ReadVeraxResults(test.path); err != nil {
			t.Errorf("#%d, |%s|: ReadVeraxResults error: |%s|", i, test.path, err)
		}

		// load gosnmp results
		var gResults = make(testResults)

		Default.Target = "127.0.0.1"
		Default.Port = test.port
		// Default.Logger = log.New(os.Stdout, "", 0) // for verbose logging
		err = Default.Connect()
		if err != nil {
			t.Errorf("%s, err |%s| Connect()", test.path, err)
		} else {
			defer Default.Conn.Close()
		}

		var oids []string
		i := 0
		oidsCount := len(vResults)
		for oid := range vResults {
			oids = append(oids, oid)
			i++
			if Partition(i, PartitonSize, oidsCount) {
				if getResults, err := Default.Get(oids); err == nil {
					for _, vb := range getResults.Variables {
						gResults[vb.Name] = vb
					}
				} else {
					t.Errorf("%s, err |%s| Get() for oids |%s|", test.path, err, oids)
				}
				i = 0
				oids = nil // "truncate" oids
			}
		}

		// compare results
		for oid, vPdu := range vResults {
			vType := vPdu.Type
			vValue := vPdu.Value
			gPdu := gResults[oid]
			gType := gPdu.Type
			gValue := gPdu.Value

			// the actual comparison testing
			if vType != gType {
				t.Errorf("vtype |%#x| doesn't match gtype |%#x| for oid |%s|", vType, gType, oid)
				continue
			}

			switch vType {
			case Integer, Gauge32, Counter32, TimeTicks, Counter64:
				vVal := ToBigInt(vValue)
				gVal := ToBigInt(gValue)
				if vVal.Cmp(gVal) != 0 {
					t.Errorf("vvalue |%v|%s| doesn't match gvalue |%v|%s| for type |%#x| oid |%s|",
						vValue, vVal, gValue, gVal, vType, oid)
				}
			case OctetString:
				var vVal, gVal string
				var ok bool
				if vVal, ok = vValue.(string); !ok {
					t.Errorf("failed string assert vvalue |%v|", vVal)
				} else if gVal, ok = gValue.(string); !ok {
					t.Errorf("failed string assert gvalue |%v|", gVal)

				} else if strings.HasPrefix(vVal, "2010-") {
					// skip weird Verax encoded hex strings
					continue
				} else if strings.HasPrefix(vVal, "2011-") {
					// skip weird Verax encoded hex strings
					continue
				} else if vVal != gVal && oid != "1.3.6.1.2.1.1.1.0" {
					// Verax mishandles 1.3.6.1.2.1.1.1.0 on Cisco device
					t.Errorf("failed string comparison\nVVAL |%s|\nGVAL |%s|\ntype |%#x| oid |%s|", vVal, gVal, vType, oid)
				}
			case ObjectIdentifier, IPAddress:
				var vVal, gVal string
				var ok bool
				if vVal, ok = vValue.(string); !ok {
					t.Errorf("failed string assert vvalue |%v|", vVal)
				} else if gVal, ok = gValue.(string); !ok {
					t.Errorf("failed string assert gvalue |%v|", gVal)
				} else if vVal != gVal {
					t.Errorf("failed comparison\nVVAL |%s|\nGVAL |%s|\ntype |%#x| oid |%s|", vVal, gVal, vType, oid)
				}
			default:
				t.Errorf("unhandled case: vtype |%#x| vvalue |%v| oid |%s|", vType, vValue, oid)
			}

		}
	}
}

func TestVeraxGetNext(t *testing.T) {

	for i, test := range veraxDevices {
		var err error

		oidMap := getNextExpected(test.port)

		// load gosnmp results
		var gResults = make(testResults)

		Default.Target = "127.0.0.1"
		Default.Port = test.port
		// Default.Logger = log.New(os.Stdout, "", 0) // for verbose logging
		err = Default.Connect()
		if err != nil {
			t.Errorf("%s, err |%s| Connect()", test.path, err)
		} else {
			defer Default.Conn.Close()
		}

		var oids []string
		oidsCount := len(oidMap)
		for oid, SNMPPacket := range oidMap {
			oids = append(oids, oid)
			if Partition(i, PartitonSize, oidsCount) {
				if getResults, err := Default.GetNext(oids); err == nil {
					for _, vb := range getResults.Variables {
						gResults[vb.Name] = vb
					}
				} else {
					t.Errorf("%s, err |%s| Get() for oids |%s|", test.path, err, oids)
				}
				i = 0
				oids = nil // "truncate" oids
			}

			// compare results
			i := 0
			for oid, gPdu := range gResults {
				vPdu := SNMPPacket.Variables[i]
				vType := vPdu.Type
				vValue := vPdu.Value
				gType := gPdu.Type
				gValue := gPdu.Value
				i++

				// the actual comparison testing
				if vType != gType {
					t.Errorf("vtype |%#x| doesn't match gtype |%#x| for oid |%s|", vType, gType, oid)
					continue
				}

				switch vType {
				case Integer, Gauge32, Counter32, TimeTicks, Counter64:
					vVal := ToBigInt(vValue)
					gVal := ToBigInt(gValue)
					if vVal.Cmp(gVal) != 0 {
						t.Errorf("vvalue |%v|%s| doesn't match gvalue |%v|%s| for type |%#x| oid |%s|",
							vValue, vVal, gValue, gVal, vType, oid)
					}
				case OctetString:
					var vVal, gVal string
					var ok bool
					if vVal, ok = vValue.(string); !ok {
						t.Errorf("failed string assert vvalue |%v|", vVal)
					} else if gVal, ok = gValue.(string); !ok {
						t.Errorf("failed string assert gvalue |%v|", gVal)

					} else if strings.HasPrefix(vVal, "2010-") {
						// skip weird Verax encoded hex strings
						continue
					} else if strings.HasPrefix(vVal, "2011-") {
						// skip weird Verax encoded hex strings
						continue
					} else if vVal != gVal && oid != "1.3.6.1.2.1.1.1.0" {
						// Verax mishandles 1.3.6.1.2.1.1.1.0 on Cisco device
						t.Errorf("failed string comparison\nVVAL |%s|\nGVAL |%s|\ntype |%#x| oid |%s|",
							vVal, gVal, vType, oid)
					}
				case ObjectIdentifier, IPAddress:
					var vVal, gVal string
					var ok bool
					if vVal, ok = vValue.(string); !ok {
						t.Errorf("failed string assert vvalue |%v|", vVal)
					} else if gVal, ok = gValue.(string); !ok {
						t.Errorf("failed string assert gvalue |%v|", gVal)
					} else if vVal != gVal {
						t.Errorf("failed comparison\nVVAL |%s|\nGVAL |%s|\ntype |%#x| oid |%s|",
							vVal, gVal, vType, oid)
					}
				default:
					t.Errorf("unhandled case: vtype |%#x| vvalue |%v| oid |%s|", vType, vValue, oid)
				}
			}
		}
	}
}

func TestVeraxGetBulk(t *testing.T) {

	for i, test := range veraxDevices {
		var err error

		oidMap := getBulkExpected(test.port)

		// load gosnmp results
		var gResults = make(testResults)

		Default.Target = "127.0.0.1"
		Default.Port = test.port
		// Default.Logger = log.New(os.Stdout, "", 0) // for verbose logging
		err = Default.Connect()
		if err != nil {
			t.Errorf("%s, err |%s| Connect()", test.path, err)
		} else {
			defer Default.Conn.Close()
		}

		var oids []string
		oidsCount := len(oidMap)
		for oid, SNMPPacket := range oidMap {
			oids = append(oids, oid)
			if Partition(i, PartitonSize, oidsCount) {
				if getResults, err := Default.GetBulk(oids, 0, 10); err == nil {
					for _, vb := range getResults.Variables {
						gResults[vb.Name] = vb
					}
				} else {
					t.Errorf("%s, err |%s| Get() for oids |%s|", test.path, err, oids)
				}
				i = 0
				oids = nil // "truncate" oids
			}

			// compare results
			i := 0
			for oid, gPdu := range gResults {
				vPdu := SNMPPacket.Variables[i]
				vName := vPdu.Name
				// doesn't always come back in order'
				for i := 0; vName != gPdu.Name; i++ {
					vPdu = SNMPPacket.Variables[i]
					vName = vPdu.Name
				}
				vType := vPdu.Type
				vValue := vPdu.Value
				gType := gPdu.Type
				gValue := gPdu.Value
				i++

				// the actual comparison testing
				if vType != gType {
					t.Errorf("vtype |%#x| doesn't match gtype |%#x| for oid |%s|", vType, gType, oid)
					continue
				}

				switch vType {
				case Integer, Gauge32, Counter32, TimeTicks, Counter64:
					vVal := ToBigInt(vValue)
					gVal := ToBigInt(gValue)
					if vVal.Cmp(gVal) != 0 {
						t.Errorf("vvalue |%v|%s| doesn't match gvalue |%v|%s| for type |%#x| oid |%s|",
							vValue, vVal, gValue, gVal, vType, oid)
					}
				case OctetString:
					var vVal, gVal string
					var ok bool
					if vVal, ok = vValue.(string); !ok {
						t.Errorf("failed string assert vvalue |%v|", vVal)
					} else if gVal, ok = gValue.(string); !ok {
						t.Errorf("failed string assert gvalue |%v|", gVal)

					} else if strings.HasPrefix(vVal, "2010-") {
						// skip weird Verax encoded hex strings
						continue
					} else if strings.HasPrefix(vVal, "2011-") {
						// skip weird Verax encoded hex strings
						continue
					} else if vVal != gVal && oid != "1.3.6.1.2.1.1.1.0" {
						// Verax mishandles 1.3.6.1.2.1.1.1.0 on Cisco device
						t.Errorf("failed string comparison\nVVAL |%s|\nGVAL |%s|\ntype |%#x| oid |%s|",
							vVal, gVal, vType, oid)
					}
				case ObjectIdentifier, IPAddress:
					var vVal, gVal string
					var ok bool
					if vVal, ok = vValue.(string); !ok {
						t.Errorf("failed string assert vvalue |%v|", vVal)
					} else if gVal, ok = gValue.(string); !ok {
						t.Errorf("failed string assert gvalue |%v|", gVal)
					} else if vVal != gVal {
						t.Errorf("failed comparison\nVVAL |%s|\nGVAL |%s|\ntype |%#x| oid |%s|",
							vVal, gVal, vType, oid)
					}
				default:
					t.Errorf("unhandled case: vtype |%#x| vvalue |%v| oid |%s|", vType, vValue, oid)
				}
			}
		}
	}
}

func getNextExpected(port uint16) map[string]*SNMPPacket {
	// maps a an oid string to an SnmpPacket
	switch port {
	case 161:
		return map[string]*SNMPPacket{
			"1.3.6.1.2.1.1.9.1.4.8": &SNMPPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.2.1.0",
						Type:  Integer,
						Value: 3,
					},
				},
			},
			"1.3.6.1.2.1.92.1.2": &SNMPPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.92.1.2.1.0",
						Type:  Counter32,
						Value: 0,
					},
				},
			},
			"1.3.6.1.2.1.1.9.1.3.52": &SNMPPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.1.9.1.4.1",
						Type:  TimeTicks,
						Value: 21,
					},
				},
			},
			"1.3.6.1.2.1.3.1.1.3.2.1.192.168.104.1": &SNMPPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.3.1.1.3.2.1.192.168.104.2",
						Type:  IPAddress,
						Value: "192.168.104.2",
					},
				},
			},
		}
	case 162:
		return map[string]*SNMPPacket{
			"1.3.6.1.2.1.3.1.1.3.2.1.192.168.104.1": &SNMPPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.3.1.1.3.9.1.192.168.1.250",
						Type:  IPAddress,
						Value: "192.168.1.250",
					},
				},
			},
			"1.3.6.1.2.1.1.9.1.4.8": &SNMPPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.1.9.1.4.9",
						Type:  TimeTicks,
						Value: 0,
					},
				},
			},
			"1.3.6.1.2.1.92.1.2": &SNMPPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.92.1.2.1.0",
						Type:  Counter32,
						Value: 0,
					},
				},
			},
			"1.3.6.1.2.1.1.9.1.5": &SNMPPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.2.1.0",
						Type:  Integer,
						Value: 30,
					},
				},
			},
		}
	default:
		return nil
	}
}

func getBulkExpected(port uint16) map[string]*SNMPPacket {
	// maps a an oid string to an SnmpPacket
	switch port {
	case 161:
		return map[string]*SNMPPacket{
			"1.3.6.1.2.1.1.9.1.4.8": &SNMPPacket{
				Version:        Version2c,
				Community:      "public",
				PDUType:        GetResponse,
				RequestID:      0,
				NonRepeaters:   0,
				MaxReps: 0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.2.1.0",
						Type:  Integer,
						Value: 3,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.1",
						Type:  Integer,
						Value: 1,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.2",
						Type:  Integer,
						Value: 2,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.3",
						Type:  Integer,
						Value: 3,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.2.1",
						Type:  OctetString,
						Value: "lo",
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.2.2",
						Type:  OctetString,
						Value: "eth0",
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.2.3",
						Type:  OctetString,
						Value: "sit0",
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.3.1",
						Type:  Integer,
						Value: 24,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.3.2",
						Type:  Integer,
						Value: 6,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.3.3",
						Type:  Integer,
						Value: 131,
					},
				},
			},
		}
	case 162:
		return map[string]*SNMPPacket{
			"1.3.6.1.2.1.1.9.1.5": &SNMPPacket{
				Version:        Version2c,
				Community:      "public",
				PDUType:        GetResponse,
				RequestID:      0,
				NonRepeaters:   0,
			  MaxReps:  			0,
				Variables: []SNMPData{
					{
						Name:  "1.3.6.1.2.1.2.1.0",
						Type:  Integer,
						Value: 30,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.1",
						Type:  Integer,
						Value: 1,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.2",
						Type:  Integer,
						Value: 2,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.3",
						Type:  Integer,
						Value: 3,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.4",
						Type:  Integer,
						Value: 4,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.5",
						Type:  Integer,
						Value: 5,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.6",
						Type:  Integer,
						Value: 6,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.7",
						Type:  Integer,
						Value: 7,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.8",
						Type:  Integer,
						Value: 8,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.9",
						Type:  Integer,
						Value: 9,
					},
				},
			},
		}
	default:
		return nil
	}
}

func ReadVeraxResults(filename string) (results testResults, err error) {
	var lines []byte
	var oidCount int64
	if lines, err = ioutil.ReadFile(filename); err != nil {
		return nil, fmt.Errorf("unable to open file %s", filename)
	}
	results = make(testResults)

	// some lines have newlines in them, therefore can't just split on newline
	linesSplit := reSplit(regexp.MustCompile(`\n\.`), string(lines), -1)
LINE:
	for _, line := range linesSplit {
		splitsA := strings.SplitN(line, " = ", 2)
		oid := splitsA[0]
		splitsB := strings.SplitN(splitsA[1], ": ", 2)
		oidType := splitsB[0]
		oidVal := strings.TrimSpace(splitsB[1])

		// removing leading . first oid
		if string(oid[0]) == "." {
			oid = oid[1:]
		}
		oidCount++
		if oidCount > OidCount {
			break LINE
		}

		var pdu SNMPData
		switch oidType {

		// listed in order of RFC2578

		case "INTEGER":
			if value, err := strconv.ParseInt(oidVal, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = Integer
				pdu.Value = value
			}

		case "STRING", "String":
			oidVal = strings.Trim(oidVal, `"`)
			oidVal = strings.Replace(oidVal, string(0x0d), "", -1)
			pdu.Type = OctetString
			pdu.Value = oidVal

		case "Hex-STRING":
			// TODO - ran out of time...
			continue LINE

		case "OID":
			pdu.Type = ObjectIdentifier
			if string(oidVal[0]) == "." {
				oidVal = oidVal[1:]
			}
			pdu.Value = oidVal

		case "BITS":
			// TODO - ran out of time...
			continue LINE

		case "IPAddress", "Network Address":
			pdu.Type = IPAddress
			pdu.Value = oidVal
			if strings.Contains(oidVal, ":") {
				// IpAddress is in "C0:A8:C4:01" format
				octets := strings.Split(oidVal, ":")
				for i, octet := range octets {
					n, _ := strconv.ParseUint(octet, 16, 8)
					octets[i] = fmt.Sprintf("%d", n)
				}
				pdu.Value = strings.Join(octets, ".")
			}

		case "Counter32":
			if value, err := strconv.ParseInt(oidVal, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = Counter32
				pdu.Value = value
			}

		case "Gauge32":
			if value, err := strconv.ParseUint(oidVal, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = Gauge32
				pdu.Value = value
			}

		case "Timeticks":
			matches := regexp.MustCompile(`\d+`).FindAllString(oidVal, 1) // pull out "(value)"
			oidVal := matches[0]
			if value, err := strconv.ParseInt(oidVal, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = TimeTicks
				pdu.Value = value
			}

		case "Counter64":
			if value, err := strconv.ParseUint(oidVal, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = Counter64
				pdu.Value = value
			}

		default:
			panic(fmt.Sprintf("Unhandled type: %s, %s\n", oidType, oidVal))
		}

		results[oid] = pdu
	}
	return results, nil
}

// re_split slices s into substrings separated by the expression and returns a slice of
// the substrings between those expression matches.
// adapted from http://codereview.appspot.com/6846048/
//
// The slice returned by this method consists of all the substrings of s
// not contained in the slice returned by FindAllString(). When called on an exp ression
// that contains no metacharacters, it is equivalent to strings.SplitN().
// Example:
// s := regexp.MustCompile("a*").re_split("abaabaccadaaae", 5)
// // s: ["", "b", "b", "c", "cadaaae"]
//
// The count determines the number of substrings to return:
// n > 0: at most n substrings; the last substring will be the unsplit remaind er.
// n == 0: the result is nil (zero substrings)
// n < 0: all substrings
func reSplit(re *regexp.Regexp, s string, n int) []string {
	if n == 0 {
		return nil
	}
	if len(s) == 0 {
		return []string{""}
	}
	matches := re.FindAllStringIndex(s, n)
	strings := make([]string, 0, len(matches))
	beg := 0
	end := 0
	for _, match := range matches {
		if n > 0 && len(strings) >= n-1 {
			break
		}
		end = match[0]
		if match[1] != 0 {
			strings = append(strings, s[beg:end])
		}
		beg = match[1]
	}
	if end != len(s) {
		strings = append(strings, s[beg:])
	}
	return strings
}
