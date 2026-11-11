package edge

import (
	"bytes"
	"encoding/binary"
	"io"

	"ngstone/internal/proto"
)

const maxControlSniff = 16 << 10

const (
	yamuxHeaderLen  = 12
	yamuxTypeData   = 0
	yamuxTypeWindow = 1
	yamuxTypePing   = 2
	controlStreamID = 1
)

func sniffShareSecret(r io.Reader) (captured []byte, secret string, ok bool) {
	read := func(n int) ([]byte, bool) {
		if len(captured)+n > maxControlSniff {
			return nil, false
		}
		start := len(captured)
		captured = append(captured, make([]byte, n)...)
		got, err := io.ReadFull(r, captured[start:])
		captured = captured[:start+got]
		if err != nil {
			return nil, false
		}
		return captured[start:], true
	}

	var stream []byte
	for {
		hdr, good := read(yamuxHeaderLen)
		if !good || hdr[0] != 0 {
			return captured, "", false
		}
		typ := hdr[1]
		id := binary.BigEndian.Uint32(hdr[4:8])
		length := binary.BigEndian.Uint32(hdr[8:12])
		switch typ {
		case yamuxTypePing:
			continue
		case yamuxTypeWindow:
			if id != controlStreamID {
				return captured, "", false
			}
			continue
		case yamuxTypeData:
			if id != controlStreamID || length > maxControlSniff {
				return captured, "", false
			}
			payload, good := read(int(length))
			if !good {
				return captured, "", false
			}
			stream = append(stream, payload...)
		default:
			return captured, "", false
		}
		if len(stream) < 4 {
			continue
		}
		n := binary.BigEndian.Uint32(stream[:4])
		if n == 0 || n > proto.MaxFrameSize {
			return captured, "", false
		}
		if uint64(len(stream)) < 4+uint64(n) {
			continue
		}
		msg, err := proto.ReadMsg(bytes.NewReader(stream[:4+n]))
		if err != nil || msg.Type != proto.TypeAuth {
			return captured, "", false
		}
		auth, err := proto.Decode[proto.Auth](msg)
		if err != nil || auth.Token != "" || auth.ShareSecret == "" {
			return captured, "", false
		}
		return captured, auth.ShareSecret, true
	}
}
