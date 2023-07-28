package ruckusweb

import (
	"context"
	"encoding/xml"
	"net"
)

type SNMP struct {
	c *Client
}

func (c *Client) SNMP() SNMP {
	return SNMP{c}
}

type SNMPv2 struct {
	Snmpv2Ap    bool   `xml:"snmpv2-ap,attr"`
	Ver         int    `xml:"ver,attr"`
	Enabled     bool   `xml:"enabled,attr"`
	SysContact  string `xml:"sys-contact,attr"`
	SysLocation string `xml:"sys-location,attr"`
	RoCommunity string `xml:"ro-community,attr"`
	RwCommunity string `xml:"rw-community,attr"`
}

func (s SNMP) GetV2(ctx context.Context) (*SNMPv2, error) {
	var req struct {
		XMLName xml.Name `xml:"snmp"`
	}
	var resp struct {
		XMLName xml.Name `xml:"resultset"`
		Snmp    SNMPv2   `xml:"snmp"`
	}

	if err := s.c.conf(ctx, confReq{
		Action: "getconf",
		Comp:   "system",
	}, &req, &resp); err != nil {
		return nil, err
	} else {
		return &resp.Snmp, nil
	}
}

func (s SNMP) SetV2(ctx context.Context, settings SNMPv2) error {
	req := struct {
		XMLName xml.Name `xml:"snmp"`
		SNMPv2
	}{SNMPv2: settings}

	return s.c.conf(ctx, confReq{
		Action: "setconf",
		Comp:   "system",
	}, &req, nil)
}

type SNMPv3 struct {
	Enabled bool `xml:"enabled,attr"`
	Ver     int  `xml:"ver,attr"`
	Snmpusr []struct {
		Role   string `xml:"role,attr"`
		Name   string `xml:"name,attr"`
		Auth   string `xml:"auth,attr"`
		AuthPP string `xml:"authPP,attr"`
		Priv   string `xml:"priv,attr"`
		PrivPP string `xml:"privPP,attr"`
	} `xml:"snmpusr"`
}

func (s SNMP) GetV3(ctx context.Context) (*SNMPv3, error) {
	var req struct {
		XMLName xml.Name `xml:"snmpv3"`
	}
	var resp struct {
		XMLName xml.Name `xml:"resultset"`
		Snmp    SNMPv3   `xml:"snmpv3"`
	}

	if err := s.c.conf(ctx, confReq{
		Action: "getconf",
		Comp:   "system",
	}, &req, &resp); err != nil {
		return nil, err
	} else {
		return &resp.Snmp, nil
	}
}

func (s SNMP) SetV3(ctx context.Context, settings SNMPv3) error {
	req := struct {
		XMLName xml.Name `xml:"snmpv3"`
		SNMPv3
	}{SNMPv3: settings}

	return s.c.conf(ctx, confReq{
		Action: "setconf",
		Comp:   "system",
	}, &req, nil)
}

type SNMPTrap struct {
	Enabled   bool   `xml:"enabled,attr"`
	Community string `xml:"community,attr"`
	Ver       int    `xml:"ver,attr"`
	Password  string `xml:"password,attr"`

	// For Ver=2:
	Ip1 net.IP `xml:"ip1,attr"`
	Ip2 net.IP `xml:"ip2,attr"`
	Ip3 net.IP `xml:"ip3,attr"`
	Ip4 net.IP `xml:"ip4,attr"`

	// For Ver=3:
	TrapV3s []SnmpTrapV3 `xml:"trapusr"`
}

type SnmpTrapV3 struct {
	Auth    string `xml:"auth,attr"`
	AuthPP  string `xml:"authPP,attr"`
	Enabled bool   `xml:"enabled,attr"`
	ID      int    `xml:"id,attr"`
	Ip      net.IP `xml:"ip,attr"`
	Name    string `xml:"name,attr"`
	Priv    string `xml:"priv,attr"`
	PrivPP  string `xml:"privPP,attr"`
}

func (s SNMP) GetTrap(ctx context.Context) (*SNMPTrap, error) {
	var req struct {
		XMLName xml.Name `xml:"snmp-trap"`
	}
	var resp struct {
		XMLName xml.Name `xml:"resultset"`
		Trap    SNMPTrap `xml:"snmp-trap"`
	}

	if err := s.c.conf(ctx, confReq{
		Action: "getconf",
		Comp:   "system",
	}, &req, &resp); err != nil {
		return nil, err
	} else {
		return &resp.Trap, nil
	}
}

func (s SNMP) SetTrap(ctx context.Context, settings SNMPTrap) error {
	req := struct {
		XMLName xml.Name `xml:"snmp-trap"`
		SNMPTrap
	}{SNMPTrap: settings}

	return s.c.conf(ctx, confReq{
		Action: "setconf",
		Comp:   "system",
	}, &req, nil)
}
