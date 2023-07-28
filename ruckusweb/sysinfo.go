package ruckusweb

import (
	"context"
	"encoding/xml"
)

type Sysinfo struct {
	Uptime        int    `xml:"uptime,attr"`
	Version       string `xml:"version,attr"`
	VersionNum    string `xml:"version-num,attr"`
	BuildNum      string `xml:"build-num,attr"`
	Model         string `xml:"model,attr"`
	Uuid          string `xml:"uuid,attr"`
	Serial        string `xml:"serial,attr"`
	Maxap         int    `xml:"maxap,attr"`
	FixedCtryCode string `xml:"fixed-ctry-code,attr"`
	EthNum        int    `xml:"eth-num,attr"`
	PoePort       string `xml:"poe-port,attr"`
	MaxConnectAp  int    `xml:"max_connect_ap,attr"`
}

/*
	AwsSns struct {
		Enabled         string `xml:"enabled,attr"`
		AwsTopicarn     string `xml:"aws-topicarn,attr"`
		AwsSnsAccesskey string `xml:"aws-sns-accesskey,attr"`
		AwsSnsSecretkey string `xml:"aws-sns-secretkey,attr"`
		AwsRegion       string `xml:"aws-region,attr"`
	} `xml:"aws-sns"`
	Pubnub struct {
		Enabled      string `xml:"enabled,attr"`
		PublishKey   string `xml:"publish-key,attr"`
		SubscribeKey string `xml:"subscribe-key,attr"`
		State        string `xml:"state,attr"`
		StatusCode   string `xml:"status_code,attr"`
	} `xml:"pubnub"`
	ZeroIt struct {
		AuthsvrID string `xml:"authsvr-id,attr"`
	} `xml:"zero-it"`
	MeshPolicy struct {
		Enabled           string `xml:"enabled,attr"`
		MaxHops           string `xml:"max-hops,attr"`
		MaxFanout         string `xml:"max-fanout,attr"`
		DetectHops        string `xml:"detect-hops,attr"`
		HopsWarnThreshold string `xml:"hops-warn-threshold,attr"`
		DetectFanout      string `xml:"detect-fanout,attr"`
		FanOutThreshold   string `xml:"fan-out-threshold,attr"`
		LoopAvoidance     string `xml:"loop-avoidance,attr"`
		GwTimeout         string `xml:"gw-timeout,attr"`
	} `xml:"mesh-policy"`
	Log struct {
		Level           string `xml:"level,attr"`
		NumEntries      string `xml:"num-entries,attr"`
		EnableRemoteLog string `xml:"enable-remote-log,attr"`
		RemoteLogServer string `xml:"remote-log-server,attr"`
	} `xml:"log"`
	Time struct {
		ByNtp                     string `xml:"by-ntp,attr"`
		Ntp1                      string `xml:"ntp1,attr"`
		Timezone                  string `xml:"timezone,attr"`
		DaylightSaving            string `xml:"daylight-saving,attr"`
		UserDefined               string `xml:"user-defined,attr"`
		UserDefinedDaylightSaving string `xml:"user-defined-daylight-saving,attr"`
		UserDefinedGmtOffset      string `xml:"user-defined-gmt-offset,attr"`
		UserDefinedDstTime        string `xml:"user-defined-dst-time,attr"`
		TzString                  string `xml:"tzString,attr"`
		Time                      string `xml:"time,attr"`
		IsDaylightSavingTime      string `xml:"is-daylight-saving-time,attr"`
	} `xml:"time"`
	UnleashedNetwork struct {
		UnleashedNetworkToken string `xml:"unleashed-network-token,attr"`
	} `xml:"unleashed-network"`

*/

func (c *Client) Sysinfo(ctx context.Context) (*Sysinfo, error) {
	var req struct {
		XMLName xml.Name `xml:"ajax-request"`
		Action  string   `xml:"action,attr"`
		Updater string   `xml:"updater,attr"`
		Comp    string   `xml:"comp,attr"`
		Sysinfo string   `xml:"sysinfo"`
	}
	req.Action = "getstat"
	req.Comp = "system"

	var resp struct {
		XMLName  xml.Name `xml:"ajax-response"`
		Response struct {
			Type     string `xml:"type,attr"`
			ID       string `xml:"id,attr"`
			Response struct {
				Text    string  `xml:",chardata"`
				Sysinfo Sysinfo `xml:"sysinfo"`
			} `xml:"response"`
		} `xml:"response"`
	}
	if err := c.cmdstat(ctx, &req, &resp); err != nil {
		return nil, err
	} else {
		return &resp.Response.Response.Sysinfo, nil
	}
}
