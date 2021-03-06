// Package abuseipdb provides a client for the AbuseIPDB API.
// See https://www.abuseipdb.com.
package abuseipdb // import "cgt.name/pkg/abuseipdb"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var baseURL = "https://www.abuseipdb.com/"

var DefaultUserAgent = "go-abuseipdb-client/1.0 (+https://cgt.name/pkg/abuseipdb)"

// Category represents an AbuseIPDB attack category.
// See https://www.abuseipdb.com/categories
type Category int16

//go:generate stringer -type=Category

const (
	// Fraudulent orders.
	CategoryFraudOrder Category = 3
	// Participating in distributed denial-of-service (usually part of botnet).
	CategoryDDoSAttack Category = 4
	// Open proxy, open relay, or Tor exit node.
	CategoryOpenProxy Category = 9
	// Comment/forum spam, HTTP referer spam, or other CMS spam.
	CategoryWebSpam Category = 10
	// Spam email content, infected attachments, phishing emails, and spoofed
	// senders (typically via exploited host or SMTP server abuse).
	// Note: Limit comments to only relevent information (instead of log dumps)
	// and be sure to remove PII if you want to remain anonymous.
	CategoryEmailSpam Category = 11
	// Scanning for open ports and vulnerable services.
	CategoryPortScan Category = 14
	// Credential brute-force attacks on webpage logins and services like SSH,
	// FTP, SIP, SMTP, RDP, etc. This category is seperate from DDoS attacks.
	CategoryBruteForce Category = 18
	// Webpage scraping (for email addresses, content, etc) and crawlers that
	// do not honor robots.txt.
	// Excessive requests and user agent spoofing can also be reported here.
	CategoryBadWebBot Category = 19
	// Host is likely infected with malware and being used for other attacks or
	// to host malicious content.
	// The host owner may not be aware of the compromise.
	// This category is often used in combination with other attack categories.
	CategoryExploitedHost Category = 20
	// Attempts to probe for or exploit installed web applications such as a CMS
	// like WordPress/Drupal, e-commerce solutions, forum software, phpMyAdmin
	// and various other software plugins/solutions.
	CategoryWebAppAttack Category = 21
	// Secure Shell (SSH) abuse.
	// Use this category in combination with more specific categories.
	CategorySSH Category = 22
	// Abuse was targeted at an "Internet of Things" type device.
	// Include information about what type of device was targeted in the comments.
	CategoryIoTTargeted Category = 23
)

// Report is an AbuseIPDB report of an IP address.
// Report is used both for submitting and receiving reports,
// but not all fields are used in both cases.
// Country, ISOCode, and Created are only used when receiving reports.
// Comment is only used when submitting reports.
// Other fields are always valid.
type Report struct {
	IP         string     `json:"ip"`
	Categories []Category `json:"category"`
	Country    string     `json:"country,omitempty"`
	ISOCode    string     `json:"isoCode,omitempty"`
	Created    time.Time  `json:"created,omitempty"`
	Comment    string     `json:"comment,omitempty"`
}

// NewReport creates a new Report with the data required for submission.
func NewReport(ip string, categories []Category, comment string) Report {
	return Report{
		IP:         ip,
		Categories: categories,
		Comment:    comment,
	}
}

// UnmarshalJSON implements the json.Unmarshaler inteface.
// A custom implementation is necessary because the standard Unmarshaler for
// time.Time expects RFC3339 format and the AbuseIPDB API uses RFC1123Z format.
func (r *Report) UnmarshalJSON(b []byte) error {
	type report struct {
		IP         string     `json:"ip"`
		Categories []Category `json:"category"`
		Country    *string    `json:"country"`
		ISOCode    *string    `json:"isoCode"`
		Created    string     `json:"created"`
		Comment    string
	}
	var rep report
	err := json.Unmarshal(b, &rep)
	if err != nil {
		return err
	}

	r.IP = rep.IP
	r.Categories = rep.Categories
	r.Comment = rep.Comment

	if rep.Country != nil {
		r.Country = *rep.Country
	}
	if rep.ISOCode != nil {
		r.ISOCode = *rep.ISOCode
	}

	t, err := time.Parse(time.RFC1123Z, rep.Created)
	if err != nil {
		return err
	}
	r.Created = t

	return nil
}

// Client is an AbuseIPDB client. Use NewClient() to instantiate.
type Client struct {
	http   *http.Client
	APIKey string
}

// NewClient initializes a new Client.
func NewClient(apiKey string) *Client {
	return &Client{
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
		APIKey: apiKey,
	}
}

// Report submits a report to AbuseIPDB.
func (c *Client) Report(r Report) error {
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

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode < 600 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return RequestError{resp.Status, body}
	}

	var ok struct {
		IP      string `json:"ip"`
		Success bool   `json:"success"`
	}
	err = json.NewDecoder(resp.Body).Decode(&ok)
	if err != nil {
		return err
	}
	if !ok.Success {
		return errors.New("API reports 'success'=false")
	}
	return nil
}

type RequestError struct {
	HTTPStatus string
	Body       []byte
}

func (e RequestError) Error() string {
	return fmt.Sprintf("API request failure: %s. Body: %s", e.HTTPStatus, e.Body)
}

// Check queries AbuseIPDB for reports of an IP address.
// Check uses the default days limit chosen by the API.
func (c *Client) Check(ip string) ([]Report, error) {
	return c.CheckDays(ip, 0)
}

// CheckDays queries AbuseIPDB for reports of an IP address.
// If days is less than 1, the parameter will be not be sent
// and the default value chosen by the API is used.
// If using the default value, use method Check instead.
func (c *Client) CheckDays(ip string, days int) ([]Report, error) {
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

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode < 600 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, RequestError{resp.Status, body}
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return nil, err
	}

	// Figure out what the type of the JSON root is (array or object),
	// so that we can unmarshal it correctly into either []Report or Report.
	// typ=0: default value (error!)
	// typ=1: array
	// typ=2: object
	var typ int
	for _, b := range buf.Bytes() {
		if b == '[' {
			typ = 1
			break
		} else if b == '{' {
			typ = 2
			break
		}
	}
	if typ == 0 {
		return nil, fmt.Errorf("JSON root isn't an object or an array: %s", buf.String())
	}

	var (
		reports []Report
		dec     = json.NewDecoder(&buf)
	)
	if typ == 1 {
		err = dec.Decode(&reports)
	} else {
		var r Report
		err = dec.Decode(&r)
		reports = append(reports, r)
	}
	return reports, err
}
