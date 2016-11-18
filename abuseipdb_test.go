package abuseipdb

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestCheckOneReport(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{
    "category": [
        5,
        15
    ],
    "country": "Turkey",
    "created": "Fri, 18 Nov 2016 17:04:02 +0000",
    "ip": "127.0.0.2",
    "isoCode": "TR"
}`))
		if err != nil {
			panic(err)
		}
	}))
	defer s.Close()
	baseURL = s.URL

	c := Client{"testapikey"}
	reports, err := c.Check("127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected len(reports) == 1, got == %d", len(reports))
	}

	expected := Report{
		IP:         "127.0.0.2",
		Country:    "Turkey",
		ISOCode:    "TR",
		Categories: []Category{5, 15},
		Created:    time.Date(2016, 11, 18, 17, 4, 2, 0, time.UTC),
	}
	// Can't make time with nil Location, so we have to change reports[0].
	reports[0].Created = reports[0].Created.In(time.UTC)
	if ok := reflect.DeepEqual(reports[0], expected); !ok {
		t.Fatalf("expected and actual are not equal.\nexpected: %#v\n  actual: %#v", expected, reports[0])
	}
}

func TestCheckMultipleReports(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`[
    {
        "category": [
            18,
            22
        ],
        "country": null,
        "created": "Fri, 18 Nov 2016 14:24:35 +0000",
        "ip": "127.0.0.9",
        "isoCode": null
    },
    {
        "category": [
            4,
            9
        ],
        "country": null,
        "created": "Fri, 18 Nov 2016 09:26:04 +0000",
        "ip": "127.0.0.9",
        "isoCode": null
    }
]`))
		if err != nil {
			panic(err)
		}
	}))
	defer s.Close()
	baseURL = s.URL

	c := Client{"testapikey"}
	reports, err := c.Check("127.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected len(reports) == 2, got == %d", len(reports))
	}

	r := reports[0]
	if r.ISOCode != "" {
		t.Error("expected empty ISOCode, got %v", r.ISOCode)
	}
	if len(r.Categories) != 2 {
		t.Error("expected len(Categories) == 2, got %d", len(r.Categories))
	}
	// Just check two fields. If they are OK, the rest are probably OK too.
}
