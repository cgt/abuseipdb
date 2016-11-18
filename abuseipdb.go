// Package abuseipdb provides a client for the AbuseIPDB service.
// See https://www.abuseipdb.com.
package abuseipdb // import "cgt.name/pkg/abuseipdb"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	baseURL = "https://www.abuseipdb.com/"
)

var DefaultUserAgent = "go-abuseipdb-client/1.0 (+https://cgt.name/pkg/abuseipdb)"

// Category represents an AbuseIPDB attack category.
// See https://www.abuseipdb.com/categories
type Category int16

const (
	// Fraudulent orders.
	FraudOrder Category = 3
	// Participating in distributed denial-of-service (usually part of botnet).
	DDoSAttack Category = 4
	// Open proxy, open relay, or Tor exit node.
	OpenProxy Category = 9
	// Comment/forum spam, HTTP referer spam, or other CMS spam.
	WebSpam Category = 10
	// Spam email content, infected attachments, phishing emails, and spoofed
	// senders (typically via exploited host or SMTP server abuse).
	// Note: Limit comments to only relevent information (instead of log dumps)
	// and be sure to remove PII if you want to remain anonymous.
	EmailSpam Category = 11
	// Scanning for open ports and vulnerable services.
	PortScan Category = 14
	// Credential brute-force attacks on webpage logins and services like SSH,
	// FTP, SIP, SMTP, RDP, etc. This category is seperate from DDoS attacks.
	BruteForce Category = 18
	// Webpage scraping (for email addresses, content, etc) and crawlers that
	// do not honor robots.txt.
	// Excessive requests and user agent spoofing can also be reported here.
	BadWebBot Category = 19
	// Host is likely infected with malware and being used for other attacks or
	// to host malicious content.
	// The host owner may not be aware of the compromise.
	// This category is often used in combination with other attack categories.
	ExploitedHost Category = 20
	// Attempts to probe for or exploit installed web applications such as a CMS
	// like WordPress/Drupal, e-commerce solutions, forum software, phpMyAdmin
	// and various other software plugins/solutions.
	WebAppAttack Category = 21
	// Secure Shell (SSH) abuse.
	// Use this category in combination with more specific categories.
	SSH Category = 22
	// Abuse was targeted at an "Internet of Things" type device.
	// Include information about what type of device was targeted in the comments.
	IoTTargeted Category = 23
)

// Report is an AbuseIPDB report of an IP address.
// TODO: Explain used for both submitting and querying.
type Report struct {
	IP         string     `json:"ip"`
	Categories []Category `json:"category"`
	Country    *string    `json:"country"`
	ISOCode    *string    `json:"isoCode"`
	Created    time.Time  `json:"created"`
	Comment    string
}

// Client is an AbuseIPDB client.
type Client struct {
	APIKey string
}

// Report submits a report to AbuseIPDB.
func (c Client) Report(r Report) error {
	if ip := net.ParseIP(r.IP); ip == nil {
		return errors.New("invalid Report.IPAddress: invalid IP")
	}

	v := url.Values{
		"key": {c.APIKey},
		"ip":  {r.IP},
	}
	if r.Comment != "" {
		v.Set("comment", r.Comment)
	}

	// Join category IDs with commas
	// Like "10,12,15"
	var buf bytes.Buffer
	for i, cat := range r.Categories {
		buf.WriteString(strconv.Itoa(int(cat)))
		// Don't write comma after the last category
		if i < len(r.Categories)-1 {
			buf.WriteByte(',')
		}
	}
	v.Set("categories", buf.String())

	req, err := http.NewRequest(http.MethodPost, baseURL+"report/json", strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response into buffer.
	// This lets us keep the raw response if the unmarshaling should fail,
	// so we can return it to the caller.
	// The API docs aren't really clear on what responses are returned when.
	buf.Reset()
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return err
	}
	var ok reportResponseOK
	err = json.Unmarshal(buf.Bytes(), &ok)
	if err != nil {
		return UnknownResponseError{resp.StatusCode, resp.Status, buf.Bytes()}
	}

	if !ok.Success {
		return errors.New("API reports 'success'=false")
	}
	return nil
}

type reportResponseOK struct {
	IP      string `json:"ip"`
	Success bool   `json:"success"`
}

// UnknownResponseError represents an unknown HTTP response from the API.
type UnknownResponseError struct {
	StatusCode int
	Status     string
	Body       []byte
}

func (e UnknownResponseError) Error() string {
	return fmt.Sprintf("status code %d, unknown response %s", e.StatusCode, e.Body)
}

// Check queries AbuseIPDB for reports of an IP address.
// Check uses the default days limit chosen by the API.
func (c Client) Check(ip string) ([]Report, error) {
	return c.CheckDays(ip, 0)
}

// CheckDays queries AbuseIPDB for reports of an IP address.
// If days is less than 1, the parameter will be not be sent
// and the default value chosen by the API is used.
// If using the default value, use method Check instead.
func (c Client) CheckDays(ip string, days int) ([]Report, error) {
	if ip := net.ParseIP(ip); ip == nil {
		return nil, errors.New("invalid Report.IPAddress: invalid IP")
	}

	v := url.Values{"key": {c.APIKey}}
	if days >= 1 {
		v.Set("days", strconv.Itoa(days))
	}
	u := fmt.Sprintf("%s/check/%s/json", baseURL, ip)
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// TODO: Finish
	// Remember: API may return single object or array of objects.

	return nil, nil
}
