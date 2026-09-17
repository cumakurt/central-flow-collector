package netflow5

import (
	"central-flow-collector/internal/decoder/netflowfixed"
	"central-flow-collector/internal/model"
	"encoding/binary"
	"errors"
)

func Decode(pkt []byte, ctx model.PacketContext) (model.DecodeResult, error) {
	if len(pkt) < 2 || binary.BigEndian.Uint16(pkt[:2]) != 5 {
		return model.DecodeResult{}, errors.New("not netflow v5")
	}
	return netflowfixed.Decode(pkt, ctx)
}
