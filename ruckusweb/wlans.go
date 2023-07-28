package ruckusweb

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type WlanEncryption int

const (
	WlanEncryptionNone WlanEncryption = iota
	WlanEncryptionWpa2
	WlanEncryptionWpa2Wpa3Mixed
	WlanEncryptionWpa3
	WlanEncryptionOwe
)

func (e WlanEncryption) MarshalText() ([]byte, error) {
	switch e {
	case WlanEncryptionNone:
		return []byte("none"), nil
	case WlanEncryptionWpa2:
		return []byte("wpa2"), nil
	case WlanEncryptionWpa2Wpa3Mixed:
		return []byte("wpa23mixed"), nil
	case WlanEncryptionWpa3:
		return []byte("wpa3"), nil
	case WlanEncryptionOwe:
		return []byte("owe"), nil
	default:
		panic("invalid WlanEncryption")
	}
}

func (e *WlanEncryption) UnmarshalText(text []byte) error {
	switch string(text) {
	case "none":
		*e = WlanEncryptionNone
	case "wpa2":
		*e = WlanEncryptionWpa2
	case "wpa23mixed":
		*e = WlanEncryptionWpa2Wpa3Mixed
	case "wpa3":
		*e = WlanEncryptionWpa3
	case "owe":
		*e = WlanEncryptionOwe
	default:
		return fmt.Errorf("invalid WLAN encryption value: %q", string(text))
	}
	return nil
}

type innerWlanQueuePriority struct {
	Voice      int `xml:"voice,attr"`
	Video      int `xml:"video,attr"`
	Data       int `xml:"data,attr"`
	Background int `xml:"background,attr"`
}

var innerWlanQueuePriorityHigh = innerWlanQueuePriority{
	Voice:      0,
	Video:      2,
	Data:       4,
	Background: 6,
}

var innerWlanQueuePriorityLow = innerWlanQueuePriority{
	Voice:      1,
	Video:      3,
	Data:       5,
	Background: 7,
}

// WlanQueuePriority is either true indicating "HIGH" priority or false indicating "LOW" priority.
type WlanQueuePriority bool

func (p *WlanQueuePriority) UnmarshalXML(d *xml.Decoder, se xml.StartElement) error {
	var i innerWlanQueuePriority
	if err := d.DecodeElement(&i, &se); err != nil {
		return err
	}
	if i == innerWlanQueuePriorityHigh {
		*p = true
		return nil
	} else if i == innerWlanQueuePriorityLow {
		*p = false
		return nil
	} else {
		return errors.New("wlan queue priority is neither HIGH nor LOW")
	}
}
func (p WlanQueuePriority) MarshalXML(e *xml.Encoder, se xml.StartElement) error {
	if p {
		return e.EncodeElement(&innerWlanQueuePriorityHigh, se)
	} else {
		return e.EncodeElement(&innerWlanQueuePriorityLow, se)
	}
}

type WlanEnablement int

const (
	WlanEnablementAlwaysOn WlanEnablement = iota
	WlanEnablementAlwaysOff
	WlanEnablementScheduled
)

/*
uplinkPreset: e.qos && e.qos.uplinkPreset ? r(e.qos.uplinkPreset) : "DISABLE",
downlinkPreset: e.qos && e.qos.downlinkPreset ? r(e.qos.downlinkPreset) : "DISABLE",
enablePerSSIDUplink: !(!e.qos || !e.qos.perssidUplinkPreset || "0" === e.qos.perssidUplinkPreset),
perssidUplinkPreset: e.qos && e.qos.perssidUplinkPreset || "0",
enablePerSSIDDownlink: !(!e.qos || !e.qos.perssidDownlinkPreset || "0" === e.qos.perssidDownlinkPreset),
perssidDownlinkPreset: e.qos && e.qos.perssidDownlinkPreset || "0"
*/
type WlanQos struct {
	UplinkPreset          string `xml:"uplink-preset,attr"`
	DownlinkPreset        string `xml:"downlink-preset,attr"`
	PerssidUplinkPreset   int    `xml:"perssid-uplink-preset,attr"`
	PerssidDownlinkPreset int    `xml:"perssid-downlink-preset,attr"`
}

/*
xSaePassphrase: e.wpa && e.wpa.xSaePassphrase || "",
saePassphrase: e.wpa && e.wpa.saePassphrase || "",
xPassphrase: e.wpa && e.wpa.xPassphrase || "",
dynamicPsk: e.wpa && e.wpa.dynamicPsk ? e.wpa.dynamicPsk : "disabled",
dynamicPskLen: e.wpa && e.wpa.dynamicPskLen || "62",
dpskType: e.wpa && e.wpa.dpskType || "friendly",
expire: e.wpa && e.wpa.expire || "0",
startPoint: e.wpa && e.wpa.startPoint || "first-use",
limitDpsk: "enabled" === (e.wpa && e.wpa.limitDpsk),
limitDpskVal: e.wpa && e.wpa.limitDpskVal || "1",
sharedDpsk: "enabled" === (e.wpa && e.wpa.sharedDpsk),
sharedDpskNum: e.wpa && e.wpa.sharedDpskNum || "2"
*/

type WlanWpa struct {
	// XPassphrase can only contain between 8 and 63 characters or 64 HEX characters, and cannot start or end with
	// space.
	XPassphrase string `xml:"x-passphrase,attr"`
	Passphrase  string `xml:"passphrase,attr"` //?
	// FIXME: Cipher should be "aes".
	Cipher string `xml:"cipher,attr"`
	/// XSaePassphrase can only contain between 8 and 63 characters, and cannot start or end with a space.
	XSaePassphrase string `xml:"x-sae-passphrase,attr"`
	/// SAEPassphrase can only contain between 8 and 63 characters, and cannot start or end with a space.
	SaePassphrase string `xml:"sae-passphrase,attr"`

	//?
	DynamicPsk    EnabledBool `xml:"dynamic-psk,attr"`
	DynamicPskLen string      `xml:"dynamic-psk-len,attr"`
	DpskType      string      `xml:"dpsk-type,attr"`
}

func (w WlanWpa) validate(needsPSK, needsSAE bool) error {
	var err error

	if needsPSK {
		if err == nil {
			err = validPSK("Passphrase", w.Passphrase)
		}
		if err == nil {
			err = validPSK("XPassphrase", w.XPassphrase)
		}
	}

	if needsSAE {
		if err == nil {
			err = validSAE("SaePassphrase", w.Passphrase)
		}
		if err == nil {
			err = validSAE("XSaePassphrase", w.XPassphrase)
		}
	}

	return err
}

func validSAE(key, passphrase string) error {
	if len(passphrase) < 8 {
		return fmt.Errorf("invalid %s: too short", key)
	}
	if len(passphrase) > 63 {
		return fmt.Errorf("invalid %s: too long", key)
	}
	if strings.HasPrefix(passphrase, " ") || strings.HasSuffix(passphrase, " ") {
		return fmt.Errorf("invalid %s: must not start or end with a space", key)
	}
	return nil
}

var reAllHex = regexp.MustCompile(`\A[0-9a-zA-Z]+\z`)

func validPSK(key, passphrase string) error {
	if len(passphrase) < 8 {
		return fmt.Errorf("invalid %s: too short", key)
	}
	if (len(passphrase) == 64 && !reAllHex.MatchString(passphrase)) || len(passphrase) > 63 {
		return fmt.Errorf("invalid %s: too long", key)
	}
	if strings.HasPrefix(passphrase, " ") || strings.HasSuffix(passphrase, " ") {
		return fmt.Errorf("invalid %s: must not start or end with a space", key)
	}
	return nil
}

// WlanSchedule describes when a Wlan should be enabled in terms of a 7-day week. Day 0 is Sunday.
type WlanSchedule [7]WlanScheduleDay

func (s WlanSchedule) MarshalXML(e *xml.Encoder, se xml.StartElement) error {
	se.Attr = []xml.Attr{
		{
			Name:  xml.Name{Local: "value"},
			Value: s.String(),
		},
	}

	var empty struct{}
	return e.EncodeElement(&empty, se)
}

func (s WlanSchedule) String() string {
	var buffer []byte
	for _, day := range s {
		var word uint64
		for i, bit := range day {
			if bit {
				word |= uint64(1 << (i % 24))
			}
			if i%24 == 23 {
				if len(buffer) > 0 {
					buffer = append(buffer, ':')
				}
				buffer = append(buffer, '0', 'x')
				buffer = strconv.AppendUint(buffer, word, 16)
				word = 0
			}
		}
	}
	return string(buffer)
}

func (s *WlanSchedule) UnmarshalXML(d *xml.Decoder, se xml.StartElement) error {
	var text []byte
	for _, attr := range se.Attr {
		if attr.Name.Space == "" && attr.Name.Local == "value" {
			text = []byte(attr.Value)
			break
		}
	}
	if text == nil {
		return errors.New("invalid WLAN schedule: no value attribute")
	}

	words := bytes.SplitN(text, []byte{':'}, 28)
	if len(words) < 28 {
		return errors.New("invalid WLAN schedule: not enough words")
	}
	for i, bWord := range words {
		if len(bWord) < 3 || bWord[0] != '0' || bWord[1] != 'x' {
			return errors.New("invalid WLAN schedule: invalid word")
		}
		word, err := strconv.ParseUint(string(bWord[2:]), 16, 64)
		if err != nil {
			return fmt.Errorf("invalid WLAN schedule: invalid word: %v", err)
		}
		for j := 0; j < 24; j++ {
			s[i/4][(i%4)*24+j] = word&1 != 0
			word = word >> 1
		}
		if word != 0 {
			return errors.New("invalid WLAN schedule: word has too many bits")
		}
	}

	var empty struct{}
	return d.DecodeElement(&empty, &se)
}

// WlanScheduleDay describes when a Wlan should be enabled in terms of 15-minute increments over a 24-hour day. Index 0
// is 00:00-00:15 UTC, index 1 is 00:15-00:30 UTC, and so on.
type WlanScheduleDay [96]bool

type WlanAuthentication int

const (
	// "open"
	WlanAuthenticationOpen WlanAuthentication = iota
	// "802.1x-eap"
	WlanAuthentication8021xEAP
	// "mac-auth"
	WlanAuthenticationMAC
)

type WlanEapType int

const (
	WlanEapTypeNone WlanEapType = iota
	// "PEAP"
	WlanEapTypePEAP
)

type Wlan struct {
	ID          int    `xml:"id,attr,omitempty"`
	Name        string `xml:"name,attr"`
	Ssid        string `xml:"ssid,attr"`
	Description string `xml:"description,attr"`
	Usage       string `xml:"usage,attr"`
	IsGuest     bool   `xml:"is-guest,attr"`

	Authentication WlanAuthentication `xml:"authentication,attr"`
	EapType        WlanEapType        `xml:"eap-type,attr,omitempty"`

	Encryption WlanEncryption `xml:"encryption,attr"`
	// Wpa must be present for WPA2- or WPA3-related Encryption, but must be absent for WlanEncryptionNone or
	// WlanEncryptionOwe.
	Wpa *WlanWpa `xml:"wpa"`

	EnableType WlanEnablement `xml:"enable-type,attr"`

	AllowIotConnect     EnabledBool       `xml:"allow-iot-connect,attr"`
	AcctsvrID           int               `xml:"acctsvr-id,attr"`
	AcctUpdInterval     int               `xml:"acct-upd-interval,attr"`
	AutoProvisioning    EnabledBool       `xml:"auto-provisioning,attr"`
	CloseSystem         bool              `xml:"close-system,attr"`
	VlanID              int               `xml:"vlan-id,attr"`
	Dvlan               EnabledBool       `xml:"dvlan,attr"`
	MaxClientsPerRadio  int               `xml:"max-clients-per-radio,attr"`
	DoWmmAc             EnabledBool       `xml:"do-wmm-ac,attr"`
	AclID               int               `xml:"acl-id,attr"`
	PolicyID            string            `xml:"policy-id,attr"`
	DevicepolicyID      string            `xml:"devicepolicy-id,attr"`
	FastBss             EnabledBool       `xml:"fast-bss,attr"`
	Bgscan              IntBool           `xml:"bgscan,attr"`
	Balance             IntBool           `xml:"balance,attr"`
	BandBalance         IntBool           `xml:"band-balance,attr"`
	Do80211d            EnabledBool       `xml:"do-802-11d,attr"`
	WlanBind            IntBool           `xml:"wlan_bind,attr"`
	ForceDhcp           IntBool           `xml:"force-dhcp,attr"`
	ForceDhcpTimeout    int               `xml:"force-dhcp-timeout,attr"`
	MaxIdleTimeout      int               `xml:"max-idle-timeout,attr"`
	IdleTimeout         bool              `xml:"idle-timeout,attr"`
	ClientIsolation     EnabledBool       `xml:"client-isolation,attr"`
	CiWhitelistID       int               `xml:"ci-whitelist-id,attr"`
	DtimPeriod          int               `xml:"dtim-period,attr"`
	DirectedMbc         int               `xml:"directed-mbc,attr"`
	ClientFlowLog       EnabledBool       `xml:"client-flow-log,attr"`
	ExportClientLog     bool              `xml:"export-client-log,attr"`
	Wifi6               bool              `xml:"wifi6,attr"`
	Do80211w            IntBool           `xml:"do-802-11w,attr"`
	WebAuth             EnabledBool       `xml:"web-auth,attr"`
	HttpsRedirection    EnabledBool       `xml:"https-redirection,attr"`
	OfdmRateOnly        bool              `xml:"ofdm-rate-only,attr"`
	BssMinrate          int               `xml:"bss-minrate,attr"`
	TxRateConfig        int               `xml:"tx-rate-config,attr"`
	CalledStationIDType int               `xml:"called-station-id-type,attr"`
	Option82            int               `xml:"option82,attr"`
	Option82Opt1        int               `xml:"option82-opt1,attr"`
	Option82Opt2        int               `xml:"option82-opt2,attr"`
	Option82Opt150      int               `xml:"option82-opt150,attr"`
	Option82Opt151      int               `xml:"option82-opt151,attr"`
	DisDgaf             int               `xml:"dis-dgaf,attr"`
	Parp                int               `xml:"parp,attr"`
	Authstats           int               `xml:"authstats,attr"`
	StaInfoExtraction   IntBool           `xml:"sta-info-extraction,attr"`
	PoolID              string            `xml:"pool-id,attr"`
	LocalBridge         IntBool           `xml:"local-bridge,attr"`
	DhcpsvrID           int               `xml:"dhcpsvr-id,attr"`
	PrecedenceID        int               `xml:"precedence-id,attr"`
	RoleBasedAccessCtrl bool              `xml:"role-based-access-ctrl,attr"`
	Option82AreaName    string            `xml:"option82-areaName,attr"`
	GuestserviceID      int               `xml:"guestservice-id,attr"`
	AuthsvrID           string            `xml:"authsvr-id,attr"`
	WlanSurvivability   string            `xml:"wlan-survivability,attr"`
	MacAddrFormat       string            `xml:"mac-addr-format,attr"`
	QueuePriority       WlanQueuePriority `xml:"queue-priority"`
	Qos                 WlanQos           `xml:"qos"`
	Rrm                 struct {
		NeighborReport EnabledBool `xml:"neighbor-report,attr"`
	} `xml:"rrm"`
	Smartcast struct {
		McastFilter EnabledBool `xml:"mcast-filter,attr"`
	} `xml:"smartcast"`
	WlanSchedule WlanSchedule `xml:"wlan-schedule"`
	AvpPolicy    struct {
		AvpEnabled EnabledBool `xml:"avp-enabled,attr"`
		AvpdenyID  int         `xml:"avpdeny-id,attr"`
	} `xml:"avp-policy"`
	UrlfilteringPolicy struct {
		UrlfilteringEnabled EnabledBool `xml:"urlfiltering-enabled,attr"`
		UrlfilteringID      int         `xml:"urlfiltering-id,attr"`
	} `xml:"urlfiltering-policy"`
	WificallingPolicy struct {
		WificallingEnabled EnabledBool `xml:"wificalling-enabled,attr"`
		ProfileID          int         `xml:"profile-id,attr"`
	} `xml:"wificalling-policy"`
}

func (w Wlan) validate() error {
	if len(w.Name) == 0 {
		return errors.New("WLAN name must be set")
	}
	if len(w.Description) == 0 {
		return errors.New("WLAN description must be set")
	}
	if len(w.Ssid) < 2 || len(w.Ssid) > 32 {
		return errors.New("SSID must be between 2 and 32 characters")
	}

	needsWpa := w.Encryption == WlanEncryptionWpa2 || w.Encryption == WlanEncryptionWpa2Wpa3Mixed || w.Encryption == WlanEncryptionWpa3
	hasWpa := w.Wpa != nil
	if needsWpa && !hasWpa {
		return errors.New("WLAN encryption requires Wpa configuration")
	} else if hasWpa && !needsWpa {
		return errors.New("WLAN encryption requires Wpa to be unconfigured")
	}

	if w.Wpa != nil {
		needsPSK := w.Encryption == WlanEncryptionWpa2 || w.Encryption == WlanEncryptionWpa2Wpa3Mixed
		needsSAE := w.Encryption == WlanEncryptionWpa3 || w.Encryption == WlanEncryptionWpa2Wpa3Mixed
		if err := w.Wpa.validate(needsPSK, needsSAE); err != nil {
			return err
		}
	}

	return nil
}

func NewWlan(name string) Wlan {
	return Wlan{
		Name:               name,
		Ssid:               name,
		Description:        name,
		Usage:              "user",
		Authentication:     WlanAuthenticationOpen,
		AcctUpdInterval:    10,
		VlanID:             1,
		MaxClientsPerRadio: 100,
		EnableType:         WlanEnablementAlwaysOn,
		AclID:              1,
		Do80211d:           true,
		ForceDhcpTimeout:   10,
		MaxIdleTimeout:     300,
		IdleTimeout:        true,
		DtimPeriod:         1,
		DirectedMbc:        1,
		Wifi6:              true,
		TxRateConfig:       1,
		StaInfoExtraction:  true,
		PrecedenceID:       1,
		QueuePriority:      true,
		Qos: WlanQos{
			UplinkPreset:          "DISABLE",
			DownlinkPreset:        "DISABLE",
			PerssidUplinkPreset:   0,
			PerssidDownlinkPreset: 0,
		},
	}
}

type Wlans struct {
	c *Client
}

func (c *Client) Wlans() Wlans {
	return Wlans{c}
}

func (w Wlans) List(ctx context.Context) ([]Wlan, error) {
	var resp struct {
		XMLName xml.Name `xml:"wlansvc-list"`
		Wlansvc []Wlan   `xml:"wlansvc"`
	}

	if err := w.c.conf(ctx, confReq{
		Action:   "getconf",
		DECRYPTX: "true",
		Comp:     "wlansvc-list",
	}, nil, &resp); err != nil {
		return nil, err
	} else {
		return resp.Wlansvc, nil
	}
}

// Create creates a Wlan.
//
// Careful: Unleashed does no validation on create and can enter crash loops when presented
// with invalid data. Recovery requires deleting the offending Wlan from the CLI.
func (w Wlans) Create(ctx context.Context, wlan Wlan) (*Wlan, error) {
	var req struct {
		XMLName xml.Name `xml:"wlansvc"`
		Wlan
	}
	req.Wlan = wlan
	req.Wlan.ID = 0 // ensure we don't specify one

	if err := req.Wlan.validate(); err != nil {
		return nil, fmt.Errorf("invalid Wlan: %v", err)
	}

	var resp struct {
		XMLName xml.Name `xml:"wlansvc"`
		Wlan
	}

	if err := w.c.conf(ctx, confReq{
		Action: "addobj",
		Comp:   "wlansvc-list",
	}, &req, &resp); err != nil {
		return nil, err
	} else {
		return &resp.Wlan, nil
	}
}

// Update updates a Wlan, replacing the record.
//
// Careful: Unleashed does no validation on update and can enter crash loops when presented
// with invalid data. Recovery requires deleting the offending Wlan from the CLI.
func (w Wlans) Update(ctx context.Context, wlan Wlan) error {
	req := struct {
		XMLName xml.Name `xml:"wlansvc"`
		Wlan
	}{
		Wlan: wlan,
	}

	if err := req.Wlan.validate(); err != nil {
		return fmt.Errorf("invalid Wlan: %v", err)
	}

	return w.c.conf(ctx, confReq{
		Action: "updobj",
		Comp:   "wlansvc-list",
	}, &req, nil)
}

// Delete a Wlan by ID.
func (w Wlans) Delete(ctx context.Context, id int) error {
	var req struct {
		XMLName xml.Name `xml:"wlansvc"`
		ID      int      `xml:"id,attr"`
	}
	req.ID = id

	return w.c.conf(ctx, confReq{
		Action: "delobj",
		Comp:   "wlansvc-list",
	}, &req, nil)
}

type WlanStatus struct {
	ID        int    `xml:"id,attr"`
	Ssid      string `xml:"ssid,attr"`
	AssocStas int    `xml:"assoc-stas,attr"`
	State     string `xml:"state,attr"`
	History   struct {
		RxBytes ByteTimeSeries `xml:"rx-bytes,attr"`
		TxBytes ByteTimeSeries `xml:"tx-bytes,attr"`
		Rssi    RssiTimeSeries `xml:"rssi,attr"`
	} `xml:"history"`
}

func (c *Client) ListStatuses(ctx context.Context) ([]WlanStatus, error) {
	var req struct {
		XMLName xml.Name `xml:"ajax-request"`
		Action  string   `xml:"action,attr"`
		Caller  string   `xml:"caller,attr"`
		Updater string   `xml:"updater,attr"`
		Comp    string   `xml:"comp,attr"`
		Wlan    struct {
			LEVEL  string `xml:"LEVEL,attr"`
			PERIOD string `xml:"PERIOD,attr"`
		} `xml:"wlan"`
	}
	req.Action = "getstat"
	req.Comp = "stamgr"
	req.Wlan.LEVEL = "1"
	req.Wlan.PERIOD = "3600"

	var resp struct {
		XMLName  xml.Name `xml:"ajax-response"`
		Response struct {
			Type         string `xml:"type,attr"`
			ID           string `xml:"id,attr"`
			ApstamgrStat struct {
				Wlan []WlanStatus `xml:"wlan"`
			} `xml:"apstamgr-stat"`
		} `xml:"response"`
	}

	if err := c.cmdstat(ctx, &req, &resp); err != nil {
		return nil, err
	} else {
		return resp.Response.ApstamgrStat.Wlan, nil
	}
}
