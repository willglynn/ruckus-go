package ruckusweb

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
)

type Client struct {
	c http.Client

	m           sync.Mutex
	host        string
	credentials Credentials
	loginResult loginResult
}

type Credentials struct {
	Username string
	Password string
}

func NewClient(Transport http.RoundTripper, host string, credentials Credentials) *Client {
	jar, _ := cookiejar.New(nil)
	c := http.Client{
		Transport: Transport,
		Jar:       jar,
	}

	// Build the client
	client := &Client{
		c: c,

		host:        host,
		credentials: credentials,
	}

	// Update the client host as we redirect
	client.c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}

		client.m.Lock()
		if req.URL.Host != client.host {
			client.host = req.URL.Host
		}
		client.m.Unlock()

		return nil
	}

	return client
}

func (c *Client) newRequestWithContext(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	c.m.Lock()
	defer c.m.Unlock()
	u := &url.URL{
		Scheme: "https",
		Host:   c.host,
		Path:   path,
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-CSRF-Token", c.loginResult.csrfToken)
	return req, nil
}

func (c *Client) postForm(ctx context.Context, path string, values url.Values) (*http.Response, error) {
	req, err := c.newRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return c.c.Do(req)
}

func (c *Client) postXml(ctx context.Context, path string, request interface{}, response interface{}) error {
	if _, err := c.getCsrfToken(ctx); err != nil {
		return err
	}

	reqBody, err := xml.Marshal(request)
	if err != nil {
		return err
	}
	log.Printf("xml request: %s", string(reqBody))

	req, err := c.newRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("XML post returned status code %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return err
	}
	log.Printf("xml response: %s", string(data))

	return xml.NewDecoder(bytes.NewReader(data)).Decode(response)
}

func (c *Client) cmdstat(ctx context.Context, request interface{}, response interface{}) error {
	return c.postXml(ctx, "/admin/_cmdstat.jsp", request, response)
}

type confReq struct {
	Action   string `xml:"action,attr"`
	DECRYPTX string `xml:"DECRYPT_X,attr,omitempty"`
	Comp     string `xml:"comp,attr"`
}

func (c *Client) conf(ctx context.Context, request confReq, requestPayload any, response interface{}) error {
	var payload []byte
	if requestPayload != nil {
		var err error
		payload, err = xml.Marshal(requestPayload)
		if err != nil {
			return err
		}
	}
	req := struct {
		XMLName  xml.Name `xml:"ajax-request"`
		Action   string   `xml:"action,attr"`
		DECRYPTX string   `xml:"DECRYPT_X,attr,omitempty"`
		Updater  string   `xml:"updater,attr"`
		Comp     string   `xml:"comp,attr"`
		Payload  []byte   `xml:",innerxml"`
	}{
		Action:   request.Action,
		DECRYPTX: request.DECRYPTX,
		Comp:     request.Comp,
		Payload:  payload,
	}

	var resp struct {
		XMLName  xml.Name `xml:"ajax-response"`
		Response struct {
			Type string `xml:"type,attr"`
			ID   string `xml:"id,attr"`
			Xmsg *xmsg  `xml:"xmsg,attr"`
			Raw  []byte `xml:",innerxml"`
		} `xml:"response"`
	}

	// HTTP error?
	if err := c.postXml(ctx, "/admin/_conf.jsp", &req, &resp); err != nil {
		return err
	}

	// Xmsg error?
	if resp.Response.Xmsg != nil {
		return resp.Response.Xmsg
	}

	if response != nil {
		// Unpack the response
		return xml.Unmarshal(resp.Response.Raw, response)
	} else {
		// Unconditional success
		return nil
	}
}

type xmsg struct {
	Type string `xml:"type,attr"`
	Msg  string `xml:"msg,attr"`
	Name string `xml:"name,attr"`
	Lmsg string `xml:"lmsg,attr"`
}

func (x xmsg) Error() string {
	return "xmsg error: " + x.Msg + ": " + x.Lmsg
}

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	if _, err := c.getCsrfToken(ctx); err != nil {
		return nil, err
	}

	req, err := c.newRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	return c.c.Do(req)
}
