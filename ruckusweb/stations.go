package ruckusweb

import (
	"context"
	"encoding/xml"
	"net"
)

type Stations struct {
	c *Client
}

func (c *Client) Stations() Stations {
	return Stations{c}
}

type Station struct {
	// Far side
	Mac        MacAddress `xml:"mac,attr"`
	Status     int        `xml:"status,attr"`
	ExtStatus  int        `xml:"ext-status,attr"`
	FirstAssoc Timestamp  `xml:"first-assoc,attr"`

	// Near side
	Ap     MacAddress `xml:"ap,attr"`
	ApName string     `xml:"ap-name,attr"`

	// AA
	User                string `xml:"user,attr"`
	VapNasid            string `xml:"vap-nasid,attr"`
	NumIntervalStats    int    `xml:"num-interval-stats,attr"`
	CalledStationIDType int    `xml:"called-station-id-type,attr"`
	AcctMultiSessionID  string `xml:"acct-multi-session-id,attr"`
	AcctSessionID       string `xml:"acct-session-id,attr"`

	Location string `xml:"location,attr"`

	// Which network?
	WlanID     int        `xml:"wlan-id,attr"`
	Wlan       string     `xml:"wlan,attr"`
	Ssid       string     `xml:"ssid,attr"`
	VapMac     MacAddress `xml:"vap-mac,attr"` // BSSID
	Encryption string     `xml:"encryption,attr"`

	GroupID          int    `xml:"group-id,attr"`
	DpskID           int    `xml:"dpsk-id,attr"`
	WpaPassphrase    string `xml:"wpa-passphrase,attr"`
	WpaPassphraseLen int    `xml:"wpa-passphrase-len,attr"`

	// How is it connected?
	Ip   net.IP `xml:"ip,attr"`
	Ipv6 net.IP `xml:"ipv6,attr"`
	Vlan int    `xml:"vlan,attr"`

	Description string `xml:"description,attr"`
	Hostname    string `xml:"hostname,attr"`

	RoleID int `xml:"role-id,attr"`

	// Fingerprinted metadata
	DeviceInfo      string `xml:"dvcinfo,attr"`
	DeviceType      string `xml:"dvctype,attr"`
	DeviceInfoGroup string `xml:"dvcinfo-group,attr"`
	Model           string `xml:"model,attr"`

	Favourite IntBool `xml:"favourite,attr"`
	Legacy    IntBool `xml:"iot,attr"`
	Blocked   IntBool `xml:"blocked,attr"`

	// The original name of the station, before any renaming.
	OriginalName string `xml:"oldname,attr"`

	// Radio properties
	Channelization         string `xml:"channelization,attr"`
	Ieee80211RadioType     string `xml:"ieee80211-radio-type,attr"`
	RadioTypeText          string `xml:"radio-type-text,attr"`
	Rssi                   int    `xml:"rssi,attr"`
	ReceivedSignalStrength int    `xml:"received-signal-strength,attr"`
	NoiseFloor             int    `xml:"noise-floor,attr"`
	RssiLevel              string `xml:"rssi-level,attr"` // excellent, healthy, ???
	AuthMethod             string `xml:"auth-method,attr"`
	AvgRssi                int    `xml:"avg-rssi,attr"`
	Channel                int    `xml:"channel,attr"`
	RadioType              string `xml:"radio-type,attr"`
	RadioBand              string `xml:"radio-band,attr"`

	// Counters
	TotalRxPkts       uint64 `xml:"total-rx-pkts,attr"`
	TotalTxPkts       uint64 `xml:"total-tx-pkts,attr"`
	TotalRetryBytes   uint64 `xml:"total-retry-bytes,attr"`
	TotalRxDup        uint64 `xml:"total-rx-dup,attr"`
	TotalTxReassoc    uint64 `xml:"total-tx-reassoc,attr"`
	TotalRxCrcErrs    uint64 `xml:"total-rx-crc-errs,attr"`
	TotalUsageBytes   uint64 `xml:"total-usage-bytes,attr"`
	TotalRxBytes      uint64 `xml:"total-rx-bytes,attr"`
	TotalTxBytes      uint64 `xml:"total-tx-bytes,attr"`
	TotalRetries      uint64 `xml:"total-retries,attr"`
	TotalRxManagement uint64 `xml:"total-rx-management,attr"`
	TotalTxManagement uint64 `xml:"total-tx-management,attr"`
	TxDropData        uint64 `xml:"tx-drop-data,attr"`
	TxDropMgmt        uint64 `xml:"tx-drop-mgmt,attr"`
}

func (s Stations) List(ctx context.Context) ([]Station, error) {
	var req struct {
		XMLName xml.Name `xml:"ajax-request"`
		Action  string   `xml:"action,attr"`
		Caller  string   `xml:"caller,attr"`
		Updater string   `xml:"updater,attr"`
		Comp    string   `xml:"comp,attr"`
		Client  struct {
			LEVEL      string `xml:"LEVEL,attr"`
			ClientType string `xml:"client-type,attr"`
		} `xml:"client"`
	}
	req.Action = "getstat"
	req.Comp = "stamgr"
	//req.Client.LEVEL = "1"
	//req.Client.ClientType = "3"

	var resp struct {
		XMLName  xml.Name `xml:"ajax-response"`
		Response struct {
			Type         string `xml:"type,attr"`
			ID           string `xml:"id,attr"`
			ApstamgrStat struct {
				Client []Station `xml:"client"`
			} `xml:"apstamgr-stat"`
		} `xml:"response"`
	}

	if err := s.c.cmdstat(ctx, &req, &resp); err != nil {
		return nil, err
	} else {
		return resp.Response.ApstamgrStat.Client, nil
	}
}

func (s Stations) ListByWlanName(ctx context.Context, wlanName string) ([]Station, error) {
	var req struct {
		XMLName xml.Name `xml:"ajax-request"`
		Action  string   `xml:"action,attr"`
		Caller  string   `xml:"caller,attr"`
		Updater string   `xml:"updater,attr"`
		Comp    string   `xml:"comp,attr"`
		Client  struct {
			Wlan     string `xml:"wlan,attr"`
			USEREGEX bool   `xml:"USE_REGEX,attr"`
		} `xml:"client"`
	}
	req.Action = "getstat"
	req.Comp = "stamgr"
	req.Client.Wlan = wlanName
	req.Client.USEREGEX = false

	var resp struct {
		XMLName  xml.Name `xml:"ajax-response"`
		Response struct {
			Type         string `xml:"type,attr"`
			ID           string `xml:"id,attr"`
			ApstamgrStat struct {
				Client []Station `xml:"client"`
			} `xml:"apstamgr-stat"`
		} `xml:"response"`
	}

	if err := s.c.cmdstat(ctx, &req, &resp); err != nil {
		return nil, err
	} else {
		return resp.Response.ApstamgrStat.Client, nil
	}
}

func (s Stations) SetFavorite(ctx context.Context, client MacAddress, favorite bool) error {
	type xcmd struct {
		Cmd    string     `xml:"cmd,attr"`
		Tag    string     `xml:"tag,attr"`
		Enable IntBool    `xml:"enable,attr"`
		Client MacAddress `xml:"client,attr"`
	}

	req := struct {
		XMLName  xml.Name `xml:"ajax-request"`
		Action   string   `xml:"action,attr"`
		AttrXcmd string   `xml:"xcmd,attr"`
		Updater  string   `xml:"updater,attr"`
		Comp     string   `xml:"comp,attr"`
		Xcmd     xcmd     `xml:"xcmd"`
	}{
		Action:   "docmd",
		AttrXcmd: "stamgr",
		Comp:     "stamgr",
		Xcmd: xcmd{
			Cmd:    "favourite",
			Tag:    "client",
			Enable: IntBool(favorite),
			Client: client,
		},
	}
	var resp struct {
		XMLName xml.Name `xml:"ajax-request"`
	}
	return s.c.cmdstat(ctx, &req, &resp)
}

func (s Stations) SetLegacy(ctx context.Context, client MacAddress, legacy bool) error {
	type xcmd struct {
		Cmd    string     `xml:"cmd,attr"`
		Tag    string     `xml:"tag,attr"`
		Enable IntBool    `xml:"enable,attr"`
		Client MacAddress `xml:"client,attr"`
	}

	req := struct {
		XMLName  xml.Name `xml:"ajax-request"`
		Action   string   `xml:"action,attr"`
		AttrXcmd string   `xml:"xcmd,attr"`
		Updater  string   `xml:"updater,attr"`
		Comp     string   `xml:"comp,attr"`
		Xcmd     xcmd     `xml:"xcmd"`
	}{
		Action:   "docmd",
		AttrXcmd: "stamgr",
		Comp:     "stamgr",
		Xcmd: xcmd{
			Cmd:    "mark-iot",
			Tag:    "client",
			Enable: IntBool(legacy),
			Client: client,
		},
	}
	var resp struct {
		XMLName xml.Name `xml:"ajax-request"`
	}
	return s.c.cmdstat(ctx, &req, &resp)
}

// SetName sets the name of a client. If the name is non-empty, the given name will override the automatic name, and the
// device will remember the client even if it disconnects. There is a limit of 500ish renamed clients.
//
// A client can be forgotten by setting it to an empty name.
func (s Stations) SetName(ctx context.Context, client MacAddress, name string) error {
	type xcmd struct {
		Cmd    string     `xml:"cmd,attr"`
		Tag    string     `xml:"tag,attr"`
		Client MacAddress `xml:"client,attr"`
		Rename string     `xml:"rename,attr"`
	}

	req := struct {
		XMLName  xml.Name `xml:"ajax-request"`
		Action   string   `xml:"action,attr"`
		AttrXcmd string   `xml:"xcmd,attr"`
		Updater  string   `xml:"updater,attr"`
		Comp     string   `xml:"comp,attr"`
		Xcmd     xcmd     `xml:"xcmd"`
	}{
		Action:   "docmd",
		AttrXcmd: "stamgr",
		Comp:     "stamgr",
		Xcmd: xcmd{
			Cmd:    "rename",
			Tag:    "client",
			Client: client,
			Rename: name,
		},
	}
	var resp struct {
		XMLName xml.Name `xml:"ajax-request"`
	}
	return s.c.cmdstat(ctx, &req, &resp)
}
