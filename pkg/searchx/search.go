// Package searchx queries the Elasticsearch index the indexer maintains.
//
// The security property that matters here is the ACL filter. Every indexed
// document carries the member list of its chat, and every query is wrapped in
// a filter on that field. A user can therefore only ever match messages from
// chats they are in — enforced by the query itself, not by post-filtering the
// results, which would leak through the total count and the pagination.
package searchx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
)

// Client wraps the Elasticsearch client with the query shapes we use.
type Client struct {
	es    *elasticsearch.Client
	index string
	// MaxResults caps a page. Deep pagination in Elasticsearch is expensive
	// and a chat search that goes past a few hundred hits is a search that
	// should be refined instead.
	MaxResults int
	Timeout    time.Duration
}

// Config describes the cluster.
type Config struct {
	Addresses []string
	Username  string
	Password  string
	APIKey    string
	CloudID   string
	Index     string
}

// Connect builds the client and verifies the cluster is reachable.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Index == "" {
		cfg.Index = "messages"
	}

	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses:     cfg.Addresses,
		Username:      cfg.Username,
		Password:      cfg.Password,
		APIKey:        cfg.APIKey,
		CloudID:       cfg.CloudID,
		RetryOnStatus: []int{502, 503, 504, 429},
		MaxRetries:    2,
	})
	if err != nil {
		return nil, fmt.Errorf("searchx: client: %w", err)
	}

	c := &Client{es: es, index: cfg.Index, MaxResults: 100, Timeout: 5 * time.Second}
	if err := c.Ping(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Ping checks the cluster; used as a readiness check.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.es.Ping(c.es.Ping.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("searchx: ping: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.IsError() {
		return fmt.Errorf("searchx: ping returned %s", resp.Status())
	}
	return nil
}

// Query describes a message search.
type Query struct {
	// UserID is the caller. Non-negotiable: it is the ACL filter.
	UserID int64
	// Text is the search terms.
	Text string
	// ChatID narrows to one conversation. Zero searches everything the user
	// can see.
	ChatID int64
	// SenderID narrows to one author.
	SenderID int64
	// From and To bound the time range.
	From time.Time
	To   time.Time

	Limit  int
	Offset int
}

// Hit is one matching message.
type Hit struct {
	MessageID string    `json:"message_id"`
	ChatID    int64     `json:"chat_id"`
	Seq       int64     `json:"seq"`
	SenderID  int64     `json:"sender_id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	// Highlight is the matched fragment with <em> markers, so the client can
	// show why a result matched without re-implementing the analyser.
	Highlight []string `json:"highlight,omitempty"`
	Score     float64  `json:"score"`
}

// Results is a page of hits.
type Results struct {
	Hits []Hit `json:"hits"`
	// Total is the number of matches, capped by track_total_hits.
	Total int64 `json:"total"`
	// TookMS is Elasticsearch's own timing, useful for spotting a slow query
	// separately from a slow network.
	TookMS int64 `json:"took_ms"`
}

// ErrEmptyQuery is returned when there is nothing to search for.
var ErrEmptyQuery = errors.New("searchx: the query text is empty")

// SearchMessages runs a full-text search restricted to the caller's chats.
func (c *Client) SearchMessages(ctx context.Context, q Query) (Results, error) {
	text := strings.TrimSpace(q.Text)
	if text == "" {
		return Results{}, ErrEmptyQuery
	}
	if q.UserID == 0 {
		// A query with no caller would search every message in the platform.
		// Refusing here rather than defaulting is the difference between a
		// bug and a breach.
		return Results{}, errors.New("searchx: a user id is required for ACL filtering")
	}

	limit := q.Limit
	if limit <= 0 || limit > c.MaxResults {
		limit = 20
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	// from + size beyond Elasticsearch's index.max_result_window (10k by
	// default) is a hard error, and a search that deep is meaningless anyway.
	if offset+limit > 1000 {
		return Results{}, fmt.Errorf("searchx: cannot page beyond 1000 results; refine the query")
	}

	// The ACL filter, and it is a filter rather than a must: filters are not
	// scored and are cached by Elasticsearch, so the check that runs on every
	// single query is also the cheapest part of it.
	filters := []map[string]any{
		{"term": map[string]any{"members": q.UserID}},
	}
	if q.ChatID != 0 {
		filters = append(filters, map[string]any{"term": map[string]any{"chat_id": q.ChatID}})
	}
	if q.SenderID != 0 {
		filters = append(filters, map[string]any{"term": map[string]any{"sender_id": q.SenderID}})
	}
	if !q.From.IsZero() || !q.To.IsZero() {
		rng := map[string]any{}
		if !q.From.IsZero() {
			rng["gte"] = q.From.UTC().Format(time.RFC3339)
		}
		if !q.To.IsZero() {
			rng["lte"] = q.To.UTC().Format(time.RFC3339)
		}
		filters = append(filters, map[string]any{"range": map[string]any{"created_at": rng}})
	}

	body := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []map[string]any{
					{
						// match, not match_phrase: people search for words
						// they half-remember, and requiring the exact phrase
						// makes search feel broken.
						"match": map[string]any{
							"body": map[string]any{
								"query": text,
								// Every term must appear, but in any order.
								// "or" would return a result for one common
								// word out of five and bury the good matches.
								"operator": "and",
								// One typo tolerated on longer words. AUTO
								// scales the edit distance with term length,
								// so short words stay exact.
								"fuzziness": "AUTO",
							},
						},
					},
				},
				"filter": filters,
			},
		},
		"highlight": map[string]any{
			"fields": map[string]any{
				"body": map[string]any{
					"fragment_size":       120,
					"number_of_fragments": 2,
					"pre_tags":            []string{"<em>"},
					"post_tags":           []string{"</em>"},
				},
			},
		},
		"sort": []map[string]any{
			// Relevance first, recency second. A chat search is usually
			// "where did we discuss X", not "what did we say most recently".
			{"_score": map[string]any{"order": "desc"}},
			{"created_at": map[string]any{"order": "desc"}},
		},
		"from": offset,
		"size": limit,
		// Counting beyond 1000 costs real work for a number nobody reads
		// precisely; "1000+" is as useful as an exact figure.
		"track_total_hits": 1000,
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return Results{}, fmt.Errorf("searchx: encode query: %w", err)
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(c.index),
		c.es.Search.WithBody(bytes.NewReader(encoded)),
	)
	if err != nil {
		return Results{}, fmt.Errorf("searchx: search: %w", err)
	}
	defer resp.Body.Close()

	if resp.IsError() {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return Results{}, fmt.Errorf("searchx: search returned %s: %s",
			resp.Status(), strings.TrimSpace(string(detail)))
	}

	return parseResults(resp.Body)
}

type esResponse struct {
	Took int64 `json:"took"`
	Hits struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []struct {
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source struct {
				ChatID    int64     `json:"chat_id"`
				Seq       int64     `json:"seq"`
				SenderID  int64     `json:"sender_id"`
				Body      string    `json:"body"`
				CreatedAt time.Time `json:"created_at"`
			} `json:"_source"`
			Highlight struct {
				Body []string `json:"body"`
			} `json:"highlight"`
		} `json:"hits"`
	} `json:"hits"`
}

func parseResults(r io.Reader) (Results, error) {
	var parsed esResponse
	if err := json.NewDecoder(io.LimitReader(r, 8<<20)).Decode(&parsed); err != nil {
		return Results{}, fmt.Errorf("searchx: decode response: %w", err)
	}

	out := Results{
		Total:  parsed.Hits.Total.Value,
		TookMS: parsed.Took,
		Hits:   make([]Hit, 0, len(parsed.Hits.Hits)),
	}
	for _, h := range parsed.Hits.Hits {
		out.Hits = append(out.Hits, Hit{
			MessageID: h.ID,
			ChatID:    h.Source.ChatID,
			Seq:       h.Source.Seq,
			SenderID:  h.Source.SenderID,
			Body:      h.Source.Body,
			CreatedAt: h.Source.CreatedAt,
			Highlight: h.Highlight.Body,
			Score:     h.Score,
		})
	}
	return out, nil
}

// DeleteChatDocuments removes every document for a chat.
//
// Called when a chat is deleted. Without it, a deleted conversation stays
// searchable — which is both a privacy failure and a very visible bug.
func (c *Client) DeleteChatDocuments(ctx context.Context, chatID int64) (int64, error) {
	body, err := json.Marshal(map[string]any{
		"query": map[string]any{"term": map[string]any{"chat_id": chatID}},
	})
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	resp, err := c.es.DeleteByQuery([]string{c.index}, bytes.NewReader(body),
		c.es.DeleteByQuery.WithContext(ctx),
		// Conflicts are expected when the indexer is writing concurrently;
		// proceeding rather than aborting means the delete completes.
		c.es.DeleteByQuery.WithConflicts("proceed"),
	)
	if err != nil {
		return 0, fmt.Errorf("searchx: delete by query: %w", err)
	}
	defer resp.Body.Close()

	if resp.IsError() {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return 0, fmt.Errorf("searchx: delete by query returned %s: %s", resp.Status(), detail)
	}

	var parsed struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return 0, nil // the delete succeeded; the count is not worth an error
	}
	return parsed.Deleted, nil
}
