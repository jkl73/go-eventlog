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

package extract

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"github.com/google/go-eventlog/tcg"
)

// DigestEquals returns an error if the Event digest does not match the slice.
func DigestEquals(e tcg.Event, b []byte) error {
	digest := e.ReplayedDigest()

	if len(digest) == 0 {
		return errors.New("no digests present")
	}
	switch len(digest) {
	case crypto.SHA384.Size():
		hasher := crypto.SHA384.New()
		hasher.Write(b)
		if bytes.Equal(hasher.Sum(nil), digest) {
			return nil
		}
	case crypto.SHA256.Size():
		s := sha256.Sum256(b)
		if bytes.Equal(s[:], digest) {
			return nil
		}
	case crypto.SHA1.Size():
		s := sha1.Sum(b)
		if bytes.Equal(s[:], digest) {
			return nil
		}
	default:
		return fmt.Errorf("cannot compare hash of length %d", len(digest))
	}

	return fmt.Errorf("digest (len %d) does not match", len(digest))
}

// verifyNullTerminatedRawData checks the digest of the data.
// Returns nil if digest match the hash of the data or the data without the last bytes (\x00).
// The caller needs to make sure len(data) is at least 1, and data is ended with '\x00',
// otherwise this function will return an error.
func verifyNullTerminatedDataDigest(hasher hash.Hash, data []byte, digest []byte) error {
	if len(data) == 0 || data[len(data)-1] != '\x00' {
		return errors.New("given data is not null-terminated")
	}
	if err := verifyDataDigest(hasher, data, digest); err != nil {
		if err := verifyDataDigest(hasher, data[:len(data)-1], digest); err != nil {
			return err
		}
	}
	return nil
}

// verifyDataDigest checks the digest of the data.
func verifyDataDigest(hasher hash.Hash, data []byte, digest []byte) error {
	hasher.Reset()
	hasher.Write(data)
	defer hasher.Reset()
	if !bytes.Equal(digest, hasher.Sum(nil)) {
		return fmt.Errorf("invalid digest: %s", hex.EncodeToString(digest))
	}
	return nil
}
