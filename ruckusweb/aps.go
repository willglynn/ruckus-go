package ruckusweb

import (
	"context"
	"encoding/xml"
	"net"
)

type APs struct {
	c *Client
}

func (c *Client) APs() APs {
	return APs{c}
}

type APStatus struct {
	Mac                MacAddress `xml:"mac,attr"`
	ID                 int        `xml:"id,attr"`
	Devname            string     `xml:"devname,attr"`
	Model              string     `xml:"model,attr"`
	State              string     `xml:"state,attr"`
	MeshState          string     `xml:"mesh-state,attr"`
	FirmwareVersion    string     `xml:"firmware-version,attr"`
	GroupID            int        `xml:"group-id,attr"`
	Ip                 net.IP     `xml:"ip,attr"`
	LastSeen           Timestamp  `xml:"last-seen,attr"`
	UptimeUpdate       string     `xml:"uptime-update,attr"`
	MeshActivated      string     `xml:"mesh-activated,attr"`
	MeshUplinkType     string     `xml:"mesh-uplink-type,attr"`
	MeshDepth          int        `xml:"mesh-depth,attr"`
	MeshMode           string     `xml:"mesh-mode,attr"`
	MeshEnabled        bool       `xml:"mesh-enabled,attr"`
	Support11ac        bool       `xml:"support-11ac,attr"`
	SerialNumber       string     `xml:"serial-number,attr"`
	ApCrashfileFlag    int        `xml:"ap-crashfile-flag,attr"`
	Role               string     `xml:"role,attr"`
	Fixed              string     `xml:"fixed,attr"`
	Priority           string     `xml:"priority,attr"`
	Channel11ng        int        `xml:"channel-11ng,attr"`
	TxPower11ng        int        `xml:"tx-power-11ng,attr"`
	Channelization11ng int        `xml:"channelization-11ng,attr"`
	Channel11na        int        `xml:"channel-11na,attr"`
	TxPower11na        int        `xml:"tx-power-11na,attr"`
	Channelization11na int        `xml:"channelization-11na,attr"`
	PoeModeWarningCode string     `xml:"poe-mode-warning-code,attr"`
	Radio              []struct {
		RadioType      string `xml:"radio-type,attr"`
		RadioBand      string `xml:"radio-band,attr"`
		Channel        int    `xml:"channel,attr"`
		Channelization int    `xml:"channelization,attr"`
		DfsChannel11na string `xml:"dfs-channel-11na,attr"`
	} `xml:"radio"`
	History struct {
		RxBytes24g ByteTimeSeries `xml:"rx-bytes-2.4g,attr"`
		TxBytes24g ByteTimeSeries `xml:"tx-bytes-2.4g,attr"`
		RxBytes5g  ByteTimeSeries `xml:"rx-bytes-5g,attr"`
		TxBytes5g  ByteTimeSeries `xml:"tx-bytes-5g,attr"`
		Rssi       RssiTimeSeries `xml:"rssi,attr"`
	} `xml:"history"`
}

func (a APs) ListStatuses(ctx context.Context) ([]APStatus, error) {
	var req struct {
		XMLName xml.Name `xml:"ajax-request"`
		Action  string   `xml:"action,attr"`
		Caller  string   `xml:"caller,attr"`
		Updater string   `xml:"updater,attr"`
		Comp    string   `xml:"comp,attr"`
		Ap      struct {
			LEVEL  string `xml:"LEVEL,attr"`
			PERIOD string `xml:"PERIOD,attr"`
		} `xml:"ap"`
	}
	req.Action = "getstat"
	req.Comp = "stamgr"
	req.Ap.LEVEL = "1"
	req.Ap.PERIOD = "3600"

	var resp struct {
		XMLName  xml.Name `xml:"ajax-response"`
		Response struct {
			Type         string `xml:"type,attr"`
			ID           string `xml:"id,attr"`
			ApstamgrStat struct {
				Ap []APStatus `xml:"ap"`
			} `xml:"apstamgr-stat"`
		} `xml:"response"`
	}

	if err := a.c.cmdstat(ctx, &req, &resp); err != nil {
		return nil, err
	} else {
		return resp.Response.ApstamgrStat.Ap, nil
	}
}

type AP struct {
	ID               int        `xml:"id,attr"`
	Mac              MacAddress `xml:"mac,attr"`
	Name             string     `xml:"name,attr"`
	Devname          string     `xml:"devname,attr"`
	Description      string     `xml:"description,attr"`
	Model            string     `xml:"model,attr"`
	UsbInstalled     bool       `xml:"usb-installed,attr"`
	PoeMode          int        `xml:"poe-mode,attr"`
	Serial           string     `xml:"serial,attr"`
	Version          string     `xml:"version,attr"`
	BuildVersion     string     `xml:"build-version,attr"`
	Approved         string     `xml:"approved,attr"`
	TunnelMode       int        `xml:"tunnel-mode,attr"`
	Ip               net.IP     `xml:"ip,attr"`
	Ipv6Addr         net.IP     `xml:"ipv6-addr,attr"`
	UdpPort          int        `xml:"udp-port,attr"`
	ConfigState      int        `xml:"config-state,attr"`
	ExtIp            net.IP     `xml:"ext-ip,attr"`
	ExtIpv6          net.IP     `xml:"ext-ipv6,attr"`
	ExtPort          int        `xml:"ext-port,attr"`
	ExtFamily        int        `xml:"ext-family,attr"`
	CbandChann       string     `xml:"cband-chann,attr"`
	MeshMode         string     `xml:"mesh-mode,attr"`
	MaxHops          string     `xml:"max-hops,attr"`
	MeshEnabled      bool       `xml:"mesh-enabled,attr"`
	Support11ac      bool       `xml:"support-11ac,attr"`
	Support11ax      bool       `xml:"support-11ax,attr"`
	AuthMode         string     `xml:"auth-mode,attr"`
	LastSeen         Timestamp  `xml:"last-seen,attr"`
	Netmask          net.IP     `xml:"netmask,attr"`
	Gateway          net.IP     `xml:"gateway,attr"`
	Dns1             net.IP     `xml:"dns1,attr"`
	Dns2             net.IP     `xml:"dns2,attr"`
	Ipv6Plen         string     `xml:"ipv6-plen,attr"`
	Ipv6Gateway      net.IP     `xml:"ipv6-gateway,attr"`
	Ipv6Dns1         net.IP     `xml:"ipv6-dns1,attr"`
	Ipv6Dns2         net.IP     `xml:"ipv6-dns2,attr"`
	StrongCert       string     `xml:"strong-cert,attr"`
	Location         string     `xml:"location,attr"`
	Gps              string     `xml:"gps,attr"`
	GroupID          int        `xml:"group-id,attr"`
	CoordinateSource string     `xml:"coordinate_source,attr"`
	ByDhcp           bool       `xml:"by-dhcp,attr"`
	AsIs             bool       `xml:"as-is,attr"`
	WorkingRadio     string     `xml:"working-radio,attr"`
	BonjourCheck     string     `xml:"bonjour-check,attr"`
	Ipmode           string     `xml:"ipmode,attr"`
	AsIsIpv6         string     `xml:"as-is-ipv6,attr"`
	LedOff           string     `xml:"led-off,attr"`
	PoeModeSetting   string     `xml:"poe-mode-setting,attr"`
	Radio            []APRadio  `xml:"radio"`
}

type APRadio struct {
	RadioType          string  `xml:"radio-type,attr"`
	Ieee80211RadioType string  `xml:"ieee80211-radio-type,attr"`
	RadioID            int     `xml:"radio-id,attr"`
	Channel            string  `xml:"channel,attr"`
	ChannelSeg2        string  `xml:"channel_seg2,attr"`
	TxPower            string  `xml:"tx-power,attr"`
	WmmAc              string  `xml:"wmm-ac,attr"`
	ProtMode           string  `xml:"prot-mode,attr"`
	VapEnabled         string  `xml:"vap-enabled,attr"`
	WlangroupID        string  `xml:"wlangroup-id,attr"`
	ChannelSelect      string  `xml:"channel-select,attr"`
	Enabled            IntBool `xml:"enabled,attr"`
	Channelization     string  `xml:"channelization,attr"`
}

func (a APs) List(ctx context.Context) ([]AP, error) {
	var resp struct {
		XMLName xml.Name `xml:"ap-list"`
		Ap      []AP     `xml:"ap"`
	}

	if err := a.c.conf(ctx, confReq{
		Action:   "getconf",
		DECRYPTX: "false",
		Comp:     "ap-list",
	}, nil, &resp); err != nil {
		return nil, err
	} else {
		return resp.Ap, nil
	}
}
