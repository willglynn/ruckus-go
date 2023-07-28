package ruckusweb

import (
	"context"
	"encoding/xml"
)

type APGroups struct {
	c *Client
}

func (c *Client) APGroups() APGroups {
	return APGroups{c}
}

type APGroup struct {
	ID          int    `xml:"id,attr"`
	Name        string `xml:"name,attr"`
	Description string `xml:"description,attr"`
	ApProperty  struct {
		Radio   []APGroupRadio `xml:"radio"`
		Network struct {
			Ipmode int `xml:"ipmode,attr"`
		} `xml:"network"`
		Mesh struct {
			MeshMode string `xml:"mesh-mode,attr"`
			MaxHops  int    `xml:"max-hops,attr"`
		} `xml:"mesh"`
		Chanfly struct {
			TurnOff     bool `xml:"turnOff,attr"`
			TurnOffTime int  `xml:"turnOff-time,attr"`
		} `xml:"chanfly"`
		Bonjourfencing struct {
			Enable IntBool `xml:"enable,attr"`
			Policy int     `xml:"policy,attr"`
		} `xml:"bonjourfencing"`
	} `xml:"ap-property"`
	Lldp struct {
		LldpInterval int         `xml:"lldp-interval,attr"`
		LldpHoldtime int         `xml:"lldp-holdtime,attr"`
		Enabled      bool        `xml:"enabled,attr"`
		LldpMgmt     EnabledBool `xml:"lldp-mgmt,attr"`
		Port         []struct {
			ID     string      `xml:"id,attr"`
			LldpOn EnabledBool `xml:"lldp-on,attr"`
		} `xml:"port"`
	} `xml:"lldp"`
	//Models    string `xml:"models"`
	Wlangroup struct {
		Wlansvc []struct {
			ID int `xml:"id,attr"`
		} `xml:"wlansvc"`
	} `xml:"wlangroup"`
}

type APGroupRadio struct {
	RadioType            string  `xml:"radio-type,attr"`
	Channel              string  `xml:"channel,attr"`
	Channelization       string  `xml:"channelization,attr"`
	AutoChannelSet       bool    `xml:"auto-channel-set,attr"`
	ChannelSet           string  `xml:"channel-set,attr"`
	TxPower              int     `xml:"tx-power,attr"`
	MixMode              int     `xml:"mix-mode,attr"`
	WlangroupID          int     `xml:"wlangroup-id,attr"`
	ChannelOutdoor       string  `xml:"channel-outdoor,attr"`
	ChannelSelect        string  `xml:"channel-select,attr"`
	ChannelOutdoorSelect string  `xml:"channel-outdoor-select,attr"`
	ChannelIndoorSelect  string  `xml:"channel-indoor-select,attr"`
	WmmAc                IntBool `xml:"wmm-ac,attr"`
	SpectralinkComp      string  `xml:"spectralink-comp,attr"`
	VapEnabled           IntBool `xml:"vap-enabled,attr"`
}

func (a APGroups) List(ctx context.Context) ([]APGroup, error) {
	var resp struct {
		XMLName xml.Name  `xml:"apgroup-list"`
		Apgroup []APGroup `xml:"apgroup"`
	}

	if err := a.c.conf(ctx, confReq{
		Action:   "getconf",
		DECRYPTX: "false",
		Comp:     "apgroup-list",
	}, nil, &resp); err != nil {
		return nil, err
	} else {
		return resp.Apgroup, nil
	}
}
