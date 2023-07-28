package ruckusweb

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"golang.org/x/net/html"
)

type loginResult struct {
	privilege string
	version   string
	csrfToken string
}

var rePrivilege = regexp.MustCompile(`var privilege = "([^"]+)"`)
var reFrameVersion = regexp.MustCompile(`var frameVersion = "([^"]+)"`)
var reCsfrToken = regexp.MustCompile(`var csfrToken = '([^"]+)'`)

func (c *Client) getCsrfToken(ctx context.Context) (string, error) {
	c.m.Lock()
	token := c.loginResult.csrfToken
	host := c.host
	c.m.Unlock()

	if token != "" && len(c.c.Jar.Cookies(&url.URL{Scheme: "https", Host: host})) > 0 {
		// We have a token and an active cookie
		// Assume we're good? &shrug;
		return token, nil
	} else {
		// Attempt to log in
		r, err := c.doLogin(ctx)
		if r != nil {
			token = r.csrfToken
		} else {
			token = ""
		}
		return token, err
	}
}

func (c *Client) doLogin(ctx context.Context) (*loginResult, error) {
	c.m.Lock()
	creds := c.credentials
	c.m.Unlock()

	// Log in
	resp, err := c.postForm(ctx, "/admin/login.jsp", url.Values{
		"username": []string{creds.Username},
		"password": []string{creds.Password},
		"ok":       []string{"Log\u00a0in"},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse the page
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, err
	}

	// Find the first script tag
	var scriptTag string
	queue := []*html.Node{doc}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		// Did we get a script tag?
		if node.Type == html.ElementNode && node.Data == "script" {
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.TextNode {
					scriptTag += child.Data
				}
			}
			break
		}

		// Did we get a meta tag?
		if node.Type == html.ElementNode && node.Data == "meta" {
			var httpEquiv, content string
			for _, attr := range node.Attr {
				if attr.Key == "http-equiv" {
					httpEquiv = attr.Val
				} else if attr.Key == "content" {
					content = attr.Val
				}
			}

			// Is it telling us the result of authentication?
			if httpEquiv == "X-Auth" {
				return nil, fmt.Errorf("login failed: %q", content)
			}
		}

		// BFS
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			queue = append(queue, child)
		}
	}
	if scriptTag == "" {
		return nil, errors.New("login failed: bad response")
	}

	result := loginResult{}
	if m := rePrivilege.FindStringSubmatch(scriptTag); m != nil {
		result.privilege = m[1]
	}
	if m := reFrameVersion.FindStringSubmatch(scriptTag); m != nil {
		result.version = m[1]
	}
	if m := reCsfrToken.FindStringSubmatch(scriptTag); m != nil {
		result.csrfToken = m[1]
	}

	c.m.Lock()
	c.loginResult = result
	c.m.Unlock()

	return &result, nil
}
