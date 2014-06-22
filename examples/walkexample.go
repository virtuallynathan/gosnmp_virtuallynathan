// Copyright 2014 Chris Dance (codedance). All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// This program demonstrates BulkWalk.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	g "github.com/virtuallynathan/gosnmp"
)

func usage() {
	fmt.Println("Usage:")
	fmt.Printf("%s host [oid]\n", filepath.Base(os.Args[0]))
	fmt.Println("host - the host to walk/scan")
	fmt.Println("oid  - the MIB/Oid defining a subtree of values")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	target := os.Args[1]
	var oid string
	if len(os.Args) > 2 {
		oid = os.Args[2]
	}

	g.Default.Target = target
	g.Default.Timeout = time.Duration(10 * time.Second) // Timeout better suited to walking
	err := g.Default.Connect()
	if err != nil {
		fmt.Printf("Connect err: %v\n", err)
		os.Exit(1)
	}
	defer g.Default.Conn.Close()

	err = g.Default.BulkWalk(oid, printValue)
	if err != nil {
		fmt.Printf("Walk Error: %v\n", err)
		os.Exit(1)
	}
}

func printValue(pdu g.SNMPData) error {
	fmt.Printf("%s = ", pdu.Name)

	switch pdu.Type {
	case g.OctetString:
		fmt.Printf("STRING: %s\n", pdu.Value.(string))
	default:
		fmt.Printf("TYPE %d: %d\n", pdu.Type, g.ToBigInt(pdu.Value))
	}
	return nil
}
