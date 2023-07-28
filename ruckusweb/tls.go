package ruckusweb

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
)

type TLS struct {
	c *Client
}

func (c *Client) TLS() TLS {
	return TLS{c}
}

// GetPrivateKey retrieves the RSA private key from the device.
func (t TLS) GetPrivateKey(ctx context.Context) (*rsa.PrivateKey, error) {
	resp, err := t.c.get(ctx, "/admin/_saveprivatekey.jsp")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid PEM data")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// GetCertificates retrieves the current certificate chain from the device.
func (t TLS) GetCertificates(ctx context.Context) ([]*x509.Certificate, error) {
	resp, err := t.c.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	certs := resp.TLS.PeerCertificates
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return certs, nil
}

// SetPrivateKey asks the device to generate a new private key.
//
// This will force a reboot.
func (t TLS) SetPrivateKey(ctx context.Context, use2048bits bool) error {
	path := "/admin/webPage/system/admin/admin_performed.jsp?cmd=regen-cert&action="
	if use2048bits {
		path += "2048"
	} else {
		path += "1024"
	}

	// Get the CSRF token
	csrf, err := t.c.getCsrfToken(ctx)
	if err != nil {
		return err
	}

	resp, err := t.c.postForm(ctx, path, url.Values{
		"cid": []string{csrf},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if !bytes.Contains(data, []byte("Action Performed")) {
		return errors.New("request failed")
	}

	// TODO: spin until recovered
	return nil
}

type CsrInput struct {
	CN string
	OU string
	O  string
	L  string
	S  string
	C  string

	// SanDNS is optional and overrides SanIP if present.
	SanDNS string
	// SanIP is optional and is overridden by SanDNS if present.
	SanIP net.IP
}

// GetCertificateRequest asks the device to generate and sign a certificate signing request for a given CsrInput.
func (t TLS) GetCertificateRequest(ctx context.Context, input CsrInput) (*x509.CertificateRequest, error) {
	var form bytes.Buffer
	var contentType string
	{
		w := multipart.NewWriter(&form)
		contentType = w.FormDataContentType()
		_ = w.WriteField("cn", input.CN)

		if input.SanDNS != "" {
			_ = w.WriteField("san-type", "DNS")
			_ = w.WriteField("dn", input.SanDNS)
		} else if len(input.SanIP) > 0 {
			_ = w.WriteField("san-type", "IP")
			_ = w.WriteField("dn", input.SanIP.String())
		} else {
			_ = w.WriteField("san-type", "IP")
			_ = w.WriteField("dn", "")
		}

		_ = w.WriteField("organ", input.O)
		_ = w.WriteField("organ-unit", input.OU)
		_ = w.WriteField("city", input.L)
		_ = w.WriteField("state", input.S)
		_ = w.WriteField("country", input.C)

		_ = w.WriteField("cc", "")
		_ = w.Close()
	}

	// ensure we're logged in
	if _, err := t.c.getCsrfToken(ctx); err != nil {
		return nil, err
	}

	// construct the request
	req, err := t.c.newRequestWithContext(ctx, http.MethodPost, "/admin/_savecert.jsp", bytes.NewReader(form.Bytes()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	// execute it
	resp, err := t.c.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("response was not a PEM-encoded certificate request")
	}

	return x509.ParseCertificateRequest(block.Bytes)
}

// SetCertificates sets the device's certificate chain to the provided certs.
//
// The first certificate in the chain must have a public key corresponding to the device's private key.
func (t TLS) SetCertificates(ctx context.Context, certs []*x509.Certificate) error {
	var form bytes.Buffer
	var contentType string
	{
		w := multipart.NewWriter(&form)
		contentType = w.FormDataContentType()

		inner, _ := w.CreateFormFile("u", "certificates.pem")
		for _, cert := range certs {
			_ = pem.Encode(inner, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
		}

		_ = w.WriteField("request_type", "xhr")
		_ = w.WriteField("action", "uploadcert")
		_ = w.WriteField("callback", "uploader_uploadcert")
		_ = w.Close()
	}

	// ensure we're logged in
	if _, err := t.c.getCsrfToken(ctx); err != nil {
		return err
	}

	// construct the request
	req, err := t.c.newRequestWithContext(ctx, http.MethodPost, "/admin/_upload.jsp", bytes.NewReader(form.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)

	// execute it
	resp, err := t.c.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Parse the response
	var respData struct {
		Msg        string `json:"msg"`
		Cf         string `json:"cf"`
		Uploadfile string `json:"uploadfile"`
		Size       int    `json:"size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return err
	}

	if respData.Msg == "I_ImportZDCertsFroSR" {
		// success
		return nil
	} else {
		// failure
		return fmt.Errorf("certificate upload failed: %q", respData.Msg)
	}
}
