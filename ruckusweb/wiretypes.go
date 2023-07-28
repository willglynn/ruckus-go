package ruckusweb

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

type EnabledBool bool

func (b EnabledBool) MarshalText() ([]byte, error) {
	if b {
		return []byte("enabled"), nil
	} else {
		return []byte("disabled"), nil
	}
}

func (b *EnabledBool) UnmarshalText(text []byte) error {
	if bytes.Equal(text, []byte("enabled")) {
		*b = true
		return nil
	} else if bytes.Equal(text, []byte("disabled")) {
		*b = false
		return nil
	}
	return fmt.Errorf("invalid EnabledBool: %q", string(text))
}

type IntBool bool

func (b IntBool) MarshalText() ([]byte, error) {
	if b {
		return []byte("1"), nil
	} else {
		return []byte("0"), nil
	}
}

func (b *IntBool) UnmarshalText(text []byte) error {
	if len(text) == 1 {
		if text[0] == '1' {
			*b = true
			return nil
		} else if text[0] == '0' {
			*b = false
			return nil
		}
	}
	return fmt.Errorf("invalid IntBool: %q", string(text))
}

type MacAddress net.HardwareAddr

func (m MacAddress) MarshalText() ([]byte, error) {
	return []byte(net.HardwareAddr(m).String()), nil
}

func (m *MacAddress) UnmarshalText(text []byte) error {
	if addr, err := net.ParseMAC(string(text)); err != nil {
		return err
	} else {
		*m = MacAddress(addr)
		return nil
	}
}

type Timestamp struct {
	time.Time
}

func (t Timestamp) MarshalText() ([]byte, error) {
	var buffer []byte
	strconv.AppendInt(buffer, t.Unix(), 10)
	return buffer, nil
}

func (t *Timestamp) UnmarshalText(text []byte) error {
	n, err := strconv.ParseInt(string(text), 10, 64)
	if err != nil {
		return err
	}
	t.Time = time.Unix(n, 0)
	return nil
}

type ByteTimeSeries []ByteTimeSeriesRecord

type ByteTimeSeriesRecord struct {
	At    time.Time
	Bytes uint64
}

func (ts ByteTimeSeries) MarshalText() ([]byte, error) {
	var buffer []byte
	for i, r := range ts {
		if i > 0 {
			buffer = append(buffer, ',')
		}
		buffer = strconv.AppendInt(buffer, r.At.Unix(), 10)
		buffer = append(buffer, ',')
		buffer = strconv.AppendUint(buffer, r.Bytes, 10)
	}
	return buffer, nil
}

func (ts *ByteTimeSeries) UnmarshalText(text []byte) error {
	for len(text) > 0 {
		var this []byte
		for i := 0; i < 15 && i < len(text); i++ {
			if text[i] == ',' {
				this = text[:i]
				text = text[i+1:]
				break
			}
		}
		if this == nil {
			return errors.New("invalid time series: odd number of elements")
		}
		at, err := strconv.ParseInt(string(this), 10, 64)
		if err != nil {
			return err
		}

		this = nil
		for i := 0; i < 15 && i < len(text); i++ {
			if text[i] == ',' {
				this = text[:i]
				text = text[i+1:]
				break
			}
		}
		if this == nil {
			this = text
			text = text[:0]
		}
		value, err := strconv.ParseUint(string(this), 10, 64)

		*ts = append(*ts, ByteTimeSeriesRecord{
			At:    time.Unix(at, 0),
			Bytes: value,
		})
	}
	return nil
}

type RssiTimeSeries []RssiTimeSeriesRecord

type RssiTimeSeriesRecord struct {
	At        time.Time
	Excellent uint32
	Moderate  uint32
	Poor      uint32
}

func (ts RssiTimeSeries) MarshalText() ([]byte, error) {
	var buffer []byte
	for i, r := range ts {
		if i > 0 {
			buffer = append(buffer, ',')
		}
		buffer = strconv.AppendInt(buffer, r.At.Unix(), 10)
		buffer = append(buffer, ',')
		buffer = strconv.AppendUint(buffer, uint64(r.Excellent), 10)
		buffer = append(buffer, ',')
		buffer = strconv.AppendUint(buffer, uint64(r.Moderate), 10)
		buffer = append(buffer, ',')
		buffer = strconv.AppendUint(buffer, uint64(r.Poor), 10)
	}
	return buffer, nil
}

func (ts *RssiTimeSeries) UnmarshalText(text []byte) error {
	for len(text) > 0 {
		var parts [4]uint64

		for partIdx := 0; partIdx < 4; partIdx++ {
			var this []byte
			for i := 0; i < 15 && i < len(text); i++ {
				if text[i] == ',' {
					this = text[:i]
					text = text[i+1:]
					break
				}
			}
			if this == nil {
				if partIdx == 3 {
					// done
					this = text
					text = text[:0]
				} else {
					return errors.New("invalid time series: number of elements not divisible by 4")
				}
			}
			n, err := strconv.ParseUint(string(this), 10, 64)
			if err != nil {
				return err
			}
			parts[partIdx] = n
		}

		*ts = append(*ts, RssiTimeSeriesRecord{
			At:        time.Unix(int64(parts[0]), 0),
			Excellent: uint32(parts[1]),
			Moderate:  uint32(parts[2]),
			Poor:      uint32(parts[3]),
		})
	}
	return nil
}
