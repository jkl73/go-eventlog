// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// Binary ccel parses and prints out a CCEL event log.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
)

var (
	eventLogPath = flag.String("eventlog", "", "Path to the event log file")
)

func main() {
	flag.Parse()

	if *eventLogPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --eventlog is required")
		flag.Usage()
		os.Exit(1)
	}

	rawEventLog, err := os.ReadFile(*eventLogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading event log file: %v\n", err)
		os.Exit(1)
	}

	x, err := tcg.ParseEventLog(rawEventLog, tcg.ParseOpts{AllowPadding: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing event log: %v\n", err)
		os.Exit(1)
	}

	// ccel is sha384 only for now
	events := x.Events(register.HashSHA384)

	for _, e := range events {
		fmt.Println("seq:        ", e.Num())
		fmt.Println("mr ind:     ", e.MRIndex())
		fmt.Println("type:       ", e.Type)
		fmt.Println("data len:   ", len(e.Data))
		fmt.Println("data:       ", strconv.Quote(string(e.Data)))
		fmt.Println("data b64:   ", string(hex.EncodeToString(e.Data)))
		fmt.Println("digest b64: ", string(hex.EncodeToString(e.Digest)))
		fmt.Println("------------------------------------------------- ")
	}
}
