// Package stun 实现 RFC 5389 的最小子集，用于获知 UDP 流被映射到的公网地址。
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	magicCookie    = 0x2112A442
	bindingRequest = 0x0001
	bindingSuccess = 0x0101
	attrMappedAddr = 0x0001
	attrXORMapped  = 0x0020
	headerLen      = 20
)

// Request 构造 Binding Request，并返回其事务 ID。
func Request() ([]byte, [12]byte) {
	var tid [12]byte
	rand.Read(tid[:])
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:], bindingRequest)
	binary.BigEndian.PutUint16(b[2:], 0)
	binary.BigEndian.PutUint32(b[4:], magicCookie)
	copy(b[8:], tid[:])
	return b, tid
}

// Parse 从 Binding Success 响应中解析映射地址。
func Parse(b []byte, tid [12]byte) (netip.AddrPort, error) {
	if len(b) < headerLen {
		return netip.AddrPort{}, errors.New("stun: 响应过短")
	}
	if binary.BigEndian.Uint16(b[0:]) != bindingSuccess {
		return netip.AddrPort{}, errors.New("stun: 不是 Binding Success 响应")
	}
	if binary.BigEndian.Uint32(b[4:]) != magicCookie || [12]byte(b[8:20]) != tid {
		return netip.AddrPort{}, errors.New("stun: 事务 ID 不匹配")
	}
	l := int(binary.BigEndian.Uint16(b[2:]))
	if headerLen+l > len(b) {
		return netip.AddrPort{}, errors.New("stun: 响应被截断")
	}
	attrs := b[headerLen : headerLen+l]
	var mapped netip.AddrPort
	for len(attrs) >= 4 {
		t := binary.BigEndian.Uint16(attrs[0:])
		al := int(binary.BigEndian.Uint16(attrs[2:]))
		if 4+al > len(attrs) {
			break
		}
		v := attrs[4 : 4+al]
		switch t {
		case attrXORMapped:
			if ap, ok := decode(v, true, b[4:20]); ok {
				return ap, nil
			}
		case attrMappedAddr:
			if ap, ok := decode(v, false, nil); ok {
				mapped = ap
			}
		}
		attrs = attrs[4+((al+3)&^3):]
	}
	if mapped.IsValid() {
		return mapped, nil
	}
	return netip.AddrPort{}, errors.New("stun: 响应中没有映射地址")
}

func decode(v []byte, xor bool, key []byte) (netip.AddrPort, bool) {
	if len(v) < 8 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:])
	if xor {
		port ^= uint16(magicCookie >> 16)
	}
	switch v[1] {
	case 0x01:
		ip := [4]byte(v[4:8])
		if xor {
			for i := range ip {
				ip[i] ^= key[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(ip), port), true
	case 0x02:
		if len(v) < 20 {
			return netip.AddrPort{}, false
		}
		ip := [16]byte(v[4:20])
		if xor {
			for i := range ip {
				ip[i] ^= key[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(ip), port), true
	}
	return netip.AddrPort{}, false
}

// Response 构造携带 addr 的 Binding Success 响应（供测试使用）。
func Response(tid [12]byte, addr netip.AddrPort) []byte {
	a := addr.Addr().Unmap()
	key := make([]byte, 16)
	binary.BigEndian.PutUint32(key, magicCookie)
	copy(key[4:], tid[:])
	val := []byte{0, 0x01, 0, 0}
	if a.Is6() {
		val[1] = 0x02
	}
	binary.BigEndian.PutUint16(val[2:], addr.Port()^uint16(magicCookie>>16))
	ip := a.AsSlice()
	for i := range ip {
		ip[i] ^= key[i]
	}
	val = append(val, ip...)
	attr := make([]byte, 4)
	binary.BigEndian.PutUint16(attr[0:], attrXORMapped)
	binary.BigEndian.PutUint16(attr[2:], uint16(len(val)))
	attr = append(attr, val...)
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:], bindingSuccess)
	binary.BigEndian.PutUint16(b[2:], uint16(len(attr)))
	binary.BigEndian.PutUint32(b[4:], magicCookie)
	copy(b[8:], tid[:])
	return append(b, attr...)
}
