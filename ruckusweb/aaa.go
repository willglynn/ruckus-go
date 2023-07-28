package ruckusweb

import (
	"context"
	"encoding/xml"
)

type AAA struct {
	c *Client
}

func (c *Client) AAA() AAA {
	return AAA{c}
}

type AaaEntry struct {
	ID       int    `xml:"id,attr"`
	Name     string `xml:"name,attr"`
	Editable bool   `xml:"EDITABLE,attr"`
	Type     string `xml:"type,attr"`
}

type AaaServer interface {
	ID() int
	Name() string
	Editable() bool
	aaaserver()
}

type AaaRadius struct {
	AaaEntry

	Encryption  EnabledBool `xml:"encryption,attr"`
	Timeout     int         `xml:"timeout,attr"`
	GroupString string      `xml:"group-string,attr"` // "memberOf"

	PrimaryRadius          *AaaRadiusEndpoint `xml:"primary-radius"`
	SecondaryRadius        *AaaRadiusEndpoint `xml:"secondary-radius"`
	Backup                 EnabledBool        `xml:"backup,attr"`
	Algorithm              string             `xml:"algorithm,attr"` // "pap", "chap"?
	FailoverRetry          int                `xml:"failover-retry,attr"`
	RetryConsecutivePacket int                `xml:"retry-consecutive-packet,attr"`
	RetryPrimaryInterval   int                `xml:"retry-primary-interval,attr"`
}

type AaaRadiusEndpoint struct {
	Ip   string `xml:"ip,attr"`
	Port uint16 `xml:"port,attr"`

	Secret  string `xml:"secret,attr"`
	XSecret string `xml:"x-secret,attr"`

	Timeout int `xml:"timeout,attr"`
	Retry   int `xml:"retry,attr"`
}

var _ AaaServer = &AaaRadius{}

func (A AaaRadius) ID() int {
	return A.AaaEntry.ID
}

func (A AaaRadius) Name() string {
	return A.AaaEntry.Name
}

func (A AaaRadius) Editable() bool {
	return A.AaaEntry.Editable
}

func (A AaaRadius) aaaserver() {
}

type AaaActiveDirectory struct {
	AaaEntry

	Encryption  EnabledBool `xml:"encryption,attr"`
	Timeout     int         `xml:"timeout,attr"`
	GroupString string      `xml:"group-string,attr"` // "memberOf"

	GlobalCatalog EnabledBool `xml:"global-catalog,attr"`
	Server1       string      `xml:"server1,attr"`
	Port          uint16      `xml:"port,attr"`
	SearchBase    string      `xml:"search-base,attr"`
	AdminDn       string      `xml:"admin-dn,attr"`
	AdminPwd      string      `xml:"admin-pwd,attr"`
	XAdminPwd     string      `xml:"x-admin-pwd,attr"`
}

func (A AaaActiveDirectory) ID() int {
	return A.AaaEntry.ID
}

func (A AaaActiveDirectory) Name() string {
	return A.AaaEntry.Name
}

func (A AaaActiveDirectory) Editable() bool {
	return A.AaaEntry.Editable
}

func (A AaaActiveDirectory) aaaserver() {
}

var _ AaaServer = &AaaActiveDirectory{}

func (a AAA) List(ctx context.Context) ([]AaaServer, error) {
	var resp struct {
		XMLName xml.Name   `xml:"authsvr-list"`
		Authsvr []AaaEntry `xml:"authsvr"`
	}

	if err := a.c.conf(ctx, confReq{
		Action:   "getconf",
		DECRYPTX: "true",
		Comp:     "authsvr-list",
	}, nil, &resp); err != nil {
		return nil, err
	} else {
		// TODO
		return nil, nil
		//return resp.Authsvr, nil
	}
}
