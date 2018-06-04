// Copyright 2018 xgfone
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netaddr

func ipv4ToUint64(bs []byte) (v uint64) {
	v += uint64(bs[0]) << 24
	v += uint64(bs[1]) << 16
	v += uint64(bs[2]) << 8
	v += uint64(bs[3])
	return
}

func ipv6ToUint64(bs []byte) (v1, v2 uint64) {
	v1 += uint64(bs[0]) << 56
	v1 += uint64(bs[1]) << 48
	v1 += uint64(bs[2]) << 40
	v1 += uint64(bs[3]) << 32
	v1 += uint64(bs[4]) << 24
	v1 += uint64(bs[5]) << 16
	v1 += uint64(bs[6]) << 8
	v1 += uint64(bs[7])

	v2 += uint64(bs[8]) << 56
	v2 += uint64(bs[9]) << 48
	v2 += uint64(bs[10]) << 40
	v2 += uint64(bs[11]) << 32
	v2 += uint64(bs[12]) << 24
	v2 += uint64(bs[13]) << 16
	v2 += uint64(bs[14]) << 8
	v2 += uint64(bs[15])

	return
}

func uint32ToBytes(v uint32) (bs [4]byte) {
	bs[3] = byte(v & 0xFF)
	bs[2] = byte((v >> 8) & 0xFF)
	bs[1] = byte((v >> 16) & 0xFF)
	bs[0] = byte((v >> 24) & 0xFF)
	return
}

func uint64ToBytes(v1, v2 uint64) (bs [16]byte) {
	bs[15] = byte(v2 & 0xFF)
	bs[14] = byte((v2 >> 8) & 0xFF)
	bs[13] = byte((v2 >> 16) & 0xFF)
	bs[12] = byte((v2 >> 24) & 0xFF)
	bs[11] = byte((v2 >> 32) & 0xFF)
	bs[10] = byte((v2 >> 40) & 0xFF)
	bs[9] = byte((v2 >> 48) & 0xFF)
	bs[8] = byte((v2 >> 56) & 0xFF)

	bs[7] = byte(v1 & 0xFF)
	bs[6] = byte((v1 >> 8) & 0xFF)
	bs[5] = byte((v1 >> 16) & 0xFF)
	bs[4] = byte((v1 >> 24) & 0xFF)
	bs[3] = byte((v1 >> 32) & 0xFF)
	bs[2] = byte((v1 >> 40) & 0xFF)
	bs[1] = byte((v1 >> 48) & 0xFF)
	bs[0] = byte((v1 >> 56) & 0xFF)

	return
}

func bytesIsZero(buf []byte) bool {
	for _, c := range buf {
		if c != 0 {
			return false
		}
	}
	return true
}

func bytesAnd(left, right []byte) []byte {
	if left == nil || right == nil || len(left) != len(right) {
		return nil
	}

	_len := len(left)
	bs := make([]byte, _len)
	for i := range left {
		bs[i] = left[i] & right[i]
	}
	return bs
}

func bytesOr(left, right []byte) []byte {
	if left == nil || right == nil || len(left) != len(right) {
		return nil
	}

	_len := len(left)
	bs := make([]byte, _len)
	for i := range left {
		bs[i] = left[i] | right[i]
	}
	return bs
}

func bytesXor(left, right []byte) []byte {
	if left == nil || right == nil || len(left) != len(right) {
		return nil
	}

	_len := len(left)
	bs := make([]byte, _len)
	for i := range left {
		bs[i] = left[i] ^ right[i]
	}
	return bs
}
