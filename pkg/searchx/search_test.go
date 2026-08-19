package searchx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
)

// The tests that matter here are about the ACL filter. A search that returns
// a message from a chat the caller is not in is a data breach, and it would
// be invisible in a functional test that only checks the happy path.

func TestQueryAlwaysCarriesTheACLFilter(t *testing.T) {
	captured := make(chan map[string]any, 1)
	c := stubClient(t, captured, `{"took":3,"hits":{"total":{"value":0},"hits":[]}}`)

	_, err := c.SearchMessages(context.Background(), Query{
		UserID: 12345,
		Text:   "hello",
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	body := <-captured
	filters := extractFilters(t, body)

	var found bool
	for _, f := range filters {
		term, ok := f["term"].(map[string]any)
		if !ok {
			continue
		}
		if v, ok := term["members"]; ok {
			found = true
			// JSON numbers decode as float64.
			if got, _ := v.(float64); int64(got) != 12345 {
				t.Fatalf("the members filter carries %v, want 12345", v)
			}
		}
	}
	if !found {
		pretty, _ := json.MarshalIndent(body, "", "  ")
		t.Fatalf("the query has no members filter — every chat in the platform would match:\n%s", pretty)
	}
}

func TestSearchRefusesWithoutACaller(t *testing.T) {
	captured := make(chan map[string]any, 1)
	c := stubClient(t, captured, `{"hits":{"total":{"value":0},"hits":[]}}`)

	// UserID zero would produce a query with no ACL filter at all.
	_, err := c.SearchMessages(context.Background(), Query{Text: "anything"})
	if err == nil {
		t.Fatal("a search with no user id was accepted")
	}
	if !strings.Contains(err.Error(), "user id") {
		t.Fatalf("got %v, want an error about the missing user id", err)
	}

	select {
	case <-captured:
		t.Fatal("the query reached Elasticsearch despite having no ACL filter")
	default:
	}
}

func TestSearchRefusesEmptyText(t *testing.T) {
	captured := make(chan map[string]any, 1)
	c := stubClient(t, captured, `{"hits":{"total":{"value":0},"hits":[]}}`)

	for _, text := range []string{"", "   ", "\t\n"} {
		if _, err := c.SearchMessages(context.Background(), Query{UserID: 1, Text: text}); !errors.Is(err, ErrEmptyQuery) {
			t.Fatalf("text %q: got %v, want ErrEmptyQuery", text, err)
		}
	}
}

func TestSearchRefusesDeepPagination(t *testing.T) {
	captured := make(chan map[string]any, 1)
	c := stubClient(t, captured, `{"hits":{"total":{"value":0},"hits":[]}}`)

	_, err := c.SearchMessages(context.Background(), Query{
		UserID: 1, Text: "x", Offset: 5000, Limit: 100,
	})
	if err == nil {
		t.Fatal("deep pagination was accepted; Elasticsearch would reject it with an opaque error")
	}
}

func TestOptionalFiltersAreAdditive(t *testing.T) {
	captured := make(chan map[string]any, 1)
	c := stubClient(t, captured, `{"hits":{"total":{"value":0},"hits":[]}}`)

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := c.SearchMessages(context.Background(), Query{
		UserID: 7, Text: "hello", ChatID: 42, SenderID: 99, From: from,
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	filters := extractFilters(t, <-captured)
	// members + chat_id + sender_id + range = 4. The members filter must
	// still be there alongside the narrowing ones.
	if len(filters) != 4 {
		pretty, _ := json.MarshalIndent(filters, "", "  ")
		t.Fatalf("expected 4 filters, got %d:\n%s", len(filters), pretty)
	}
}

func TestParseResults(t *testing.T) {
	captured := make(chan map[string]any, 1)
	c := stubClient(t, captured, `{
      "took": 12,
      "hits": {
        "total": {"value": 2},
        "hits": [
          {
            "_id": "msg-1", "_score": 3.5,
            "_source": {"chat_id": 42, "seq": 100, "sender_id": 7,
                        "body": "hello world", "created_at": "2026-01-01T10:00:00Z"},
            "highlight": {"body": ["<em>hello</em> world"]}
          },
          {
            "_id": "msg-2", "_score": 1.2,
            "_source": {"chat_id": 42, "seq": 90, "sender_id": 8,
                        "body": "hello again", "created_at": "2026-01-01T09:00:00Z"}
          }
        ]
      }
    }`)

	res, err := c.SearchMessages(context.Background(), Query{UserID: 7, Text: "hello"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	<-captured

	if res.Total != 2 || len(res.Hits) != 2 {
		t.Fatalf("total=%d hits=%d, want 2 and 2", res.Total, len(res.Hits))
	}
	if res.TookMS != 12 {
		t.Fatalf("took = %d, want 12", res.TookMS)
	}

	first := res.Hits[0]
	if first.MessageID != "msg-1" || first.ChatID != 42 || first.Seq != 100 {
		t.Fatalf("first hit: %+v", first)
	}
	if len(first.Highlight) != 1 || !strings.Contains(first.Highlight[0], "<em>") {
		t.Fatalf("highlight not parsed: %v", first.Highlight)
	}
	if res.Hits[1].Highlight != nil {
		t.Fatalf("a hit with no highlight produced %v", res.Hits[1].Highlight)
	}
}

func TestSearchSurfacesClusterErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_search") {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"reason":"all shards failed"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	es, err := elasticsearch.NewClient(elasticsearch.Config{Addresses: []string{srv.URL}})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	c := &Client{es: es, index: "messages", MaxResults: 100, Timeout: 5 * time.Second}

	if _, err := c.SearchMessages(context.Background(), Query{UserID: 1, Text: "x"}); err == nil {
		t.Fatal("a failing cluster returned no error")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// stubClient returns a Client pointed at a server that captures the query
// body and replies with a fixed document.
func stubClient(t *testing.T, captured chan map[string]any, reply string) *Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_search") {
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err == nil {
				select {
				case captured <- body:
				default:
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Elastic-Product", "Elasticsearch")
			_, _ = w.Write([]byte(reply))
			return
		}
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	es, err := elasticsearch.NewClient(elasticsearch.Config{Addresses: []string{srv.URL}})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return &Client{es: es, index: "messages", MaxResults: 100, Timeout: 5 * time.Second}
}

func extractFilters(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()

	query, ok := body["query"].(map[string]any)
	if !ok {
		t.Fatal("the request body has no query")
	}
	boolQuery, ok := query["bool"].(map[string]any)
	if !ok {
		t.Fatal("the query is not a bool query, so it carries no filter clause")
	}
	raw, ok := boolQuery["filter"].([]any)
	if !ok {
		t.Fatal("the bool query has no filter clause at all")
	}

	out := make([]map[string]any, 0, len(raw))
	for _, f := range raw {
		if m, ok := f.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
