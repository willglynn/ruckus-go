package ruckusweb

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewWlan(t *testing.T) {
	example := NewWlan("foo")
	assert.Equal(t, example.Description, "foo")
	assert.Equal(t, example.Name, "foo")
	assert.Equal(t, example.Ssid, "foo")
}

func TestWlanQueuePriority_MarshalXML(t *testing.T) {
	type args struct {
		e  *xml.Encoder
		se xml.StartElement
	}
	tests := []struct {
		name     string
		p        WlanQueuePriority
		expected string
	}{
		{
			"high",
			WlanQueuePriority(true),
			"<WlanQueuePriority voice=\"0\" video=\"2\" data=\"4\" background=\"6\"></WlanQueuePriority>",
		},
		{
			"low",
			WlanQueuePriority(false),
			"<WlanQueuePriority voice=\"1\" video=\"3\" data=\"5\" background=\"7\"></WlanQueuePriority>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := xml.Marshal(tt.p)
			assert.Nil(t, err)
			assert.Equal(t, string(got), tt.expected)
		})
	}
}

func TestWlanSchedule_String(t *testing.T) {
	tests := []struct {
		name string
		s    WlanSchedule
		want string
	}{
		{
			"Blank",
			WlanSchedule{},
			"0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.s.String()
			if got != tt.want {
				t.Errorf("String() got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWlanSchedule_Unmarshal(t *testing.T) {
	type args struct {
		text []byte
	}
	tests := []struct {
		name    string
		input   string
		want    WlanSchedule
		wantErr bool
	}{
		{
			"Blank",
			"<wlan-schedule value='0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0'/>",
			WlanSchedule{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got WlanSchedule
			if err := xml.Unmarshal([]byte(tt.input), &got); (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
