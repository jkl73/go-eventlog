// Copyright 2026 Google LLC
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

// Package gmes has configs for extracting information from Google measurements.
package gmes

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// MeasurementEvent represents the structure of a Google measurement event.
type MeasurementEvent struct {
	Version uint32
	Tag     uint32
	Size    uint32
	Content []byte
}

type registerConfig struct {
	BMCFirmwareIdx uint32
	MBMIdx         uint32
	BIOSIdx        uint32
	HostKernelIdx  uint32
}

type measurementTagConfig struct {
	BMCFirmware uint32
	MBM         uint32
	HostKernel  uint32
	BIOS        uint32
}

// PCRConfig configures the expected PCR indexes for GMES event logs.
var PCRConfig = registerConfig{
	BMCFirmwareIdx: 0,
	MBMIdx:         11,
	BIOSIdx:        17,
	HostKernelIdx:  21,
}

// MeasurementTagConfig configures the expected measurement tags for GMES events.
var MeasurementTagConfig = measurementTagConfig{
	BMCFirmware: 1,
	BIOS:        2,
	HostKernel:  3,
	MBM:         4,
}

// EventID is the expected event ID for GMES events.
var EventID uint32 = 0x474D4553

// ParseEvent parses a GMES event from the given data.
func ParseEvent(eventdata []byte) (*MeasurementEvent, error) {
	r := bytes.NewReader(eventdata)

	measurement := &MeasurementEvent{}

	if err := binary.Read(r, binary.LittleEndian, &measurement.Version); err != nil {
		return nil, fmt.Errorf("failed to parse measurement version: %v", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &measurement.Tag); err != nil {
		return nil, fmt.Errorf("failed to parse measurement tag: %v", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &measurement.Size); err != nil {
		return nil, fmt.Errorf("failed to parse measurement size: %v", err)
	}

	measurement.Content = make([]byte, measurement.Size)
	if _, err := r.Read(measurement.Content); err != nil {
		return nil, fmt.Errorf("failed to parse measurement content: %v", err)
	}

	return measurement, nil
}
