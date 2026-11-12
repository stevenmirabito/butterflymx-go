package graphql

import (
	"context"
	"encoding/json/v2"
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestOperationDocuments(t *testing.T) {
	spread := regexp.MustCompile(`\.\.\.\s*([A-Za-z_]\w*)`)
	for _, op := range allOperations() {
		t.Run(op.Name, func(t *testing.T) {
			if !regexp.MustCompile(`(^|\s)query ` + op.Name + `\b`).MatchString(op.Document) {
				t.Errorf("document lacks `query %s`", op.Name)
			}
			for _, m := range spread.FindAllStringSubmatch(op.Document, -1) {
				if m[1] == "on" {
					continue
				}
				if !strings.Contains(op.Document, "fragment "+m[1]+" on ") {
					t.Errorf("fragment %s has no definition", m[1])
				}
			}
			if strings.Count(op.Document, "{") != strings.Count(op.Document, "}") {
				t.Error("unbalanced braces")
			}
		})
	}
}

func TestRequestMarshal(t *testing.T) {
	b, err := json.Marshal(Request{OperationName: "X", Query: "query X{a}"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "variables") || strings.Contains(string(b), "extensions") {
		t.Errorf("nil variables/extensions not omitted: %s", b)
	}
	b, err = json.Marshal(NewRequest(Tenants, map[string]any{"after": ""}))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"after":""`) || !strings.Contains(s, `"operationName":"Tenants"`) ||
		!strings.Contains(s, `"apollo-ios"`) || !strings.Contains(s, `"2.4.0"`) {
		t.Errorf("unexpected body: %s", s)
	}
}

type userData struct {
	CurrentUser struct {
		ID string `json:"id"`
	} `json:"currentUser"`
}

func TestDecode(t *testing.T) {
	var d userData
	partial, err := Decode([]byte(`{"data":{"currentUser":{"id":"1"}}}`), &d)
	if err != nil || partial != nil || d.CurrentUser.ID != "1" {
		t.Fatalf("data only: %v %v %+v", partial, err, d)
	}

	_, err = Decode([]byte(`{"data":null,"errors":[{"message":"boom"},{"message":"bang"}]}`), &d)
	var es Errors
	if !errors.As(err, &es) || len(es) != 2 || !strings.Contains(err.Error(), "boom; bang") {
		t.Fatalf("errors only: %v", err)
	}
	if _, err = Decode([]byte(`{"errors":[{"message":"x","path":["a",0]}]}`), &d); !errors.As(err, &es) {
		t.Fatalf("absent data: %v", err)
	}
	if _, err = Decode([]byte(`{}`), &d); err == nil {
		t.Fatal("expected error for empty response")
	}

	d = userData{}
	partial, err = Decode([]byte(`{"data":{"currentUser":{"id":"2"}},"errors":[{"message":"warn"}]}`), &d)
	if err != nil || len(partial) != 1 || partial[0].Message != "warn" || d.CurrentUser.ID != "2" {
		t.Fatalf("partial: %v %v %+v", partial, err, d)
	}

	var nodes struct {
		Nodes []*struct {
			ID string `json:"id"`
		} `json:"nodes"`
	}
	partial, err = Decode([]byte(`{"data":{"nodes":[{"id":"a"},null,{"id":"c"}]},"errors":[{"message":"denied"}]}`), &nodes)
	if err != nil || len(partial) != 1 || len(nodes.Nodes) != 3 || nodes.Nodes[1] != nil || nodes.Nodes[2].ID != "c" {
		t.Fatalf("null node: %v %v %+v", partial, err, nodes)
	}

	if _, err = Decode([]byte(`{"data":`), &d); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestConnectionNullCursor(t *testing.T) {
	var c Connection[int]
	if err := json.Unmarshal([]byte(`{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[1,2]}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.PageInfo.EndCursor != "" || len(c.Nodes) != 2 {
		t.Fatalf("%+v", c)
	}
}

func TestPagesMultiple(t *testing.T) {
	var afters []string
	fetch := func(_ context.Context, after string) ([]int, PageInfo, error) {
		afters = append(afters, after)
		switch after {
		case "":
			return []int{1, 2}, PageInfo{true, "c1"}, nil
		case "c1":
			return []int{3}, PageInfo{true, "c2"}, nil
		default:
			return []int{4}, PageInfo{}, nil
		}
	}
	var got []int
	for v, err := range Pages(context.Background(), fetch) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, v)
	}
	if len(got) != 4 || got[3] != 4 || len(afters) != 3 || afters[0] != "" {
		t.Fatalf("got %v afters %v", got, afters)
	}
}

func TestPagesEarlyBreak(t *testing.T) {
	calls := 0
	fetch := func(_ context.Context, after string) ([]int, PageInfo, error) {
		calls++
		return []int{1, 2}, PageInfo{true, "c" + after}, nil
	}
	for range Pages(context.Background(), fetch) {
		break
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestPagesRepeatedCursor(t *testing.T) {
	fetch := func(_ context.Context, after string) ([]int, PageInfo, error) {
		return []int{1}, PageInfo{true, "same"}, nil
	}
	var n int
	var gotErr error
	for _, err := range Pages(context.Background(), fetch) {
		if err != nil {
			gotErr = err
			break
		}
		n++
	}
	if gotErr == nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, gotErr)
	}
}

func TestPagesMaxPages(t *testing.T) {
	i := 0
	fetch := func(_ context.Context, after string) ([]int, PageInfo, error) {
		i++
		return nil, PageInfo{true, string(rune('a'+i%26)) + strings.Repeat("x", i)}, nil
	}
	var gotErr error
	for _, err := range Pages(context.Background(), fetch) {
		gotErr = err
	}
	if gotErr == nil || i != MaxPages {
		t.Fatalf("i=%d err=%v", i, gotErr)
	}
}

func TestPagesContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fetch := func(_ context.Context, after string) ([]int, PageInfo, error) {
		cancel()
		return []int{1}, PageInfo{true, "n" + after}, nil
	}
	var gotErr error
	for _, err := range Pages(ctx, fetch) {
		gotErr = err
	}
	if !errors.Is(gotErr, context.Canceled) {
		t.Fatalf("err = %v", gotErr)
	}
}

func TestPagesFetchError(t *testing.T) {
	boom := errors.New("boom")
	fetch := func(_ context.Context, after string) ([]int, PageInfo, error) {
		if after == "" {
			return []int{1}, PageInfo{true, "c"}, nil
		}
		return nil, PageInfo{}, boom
	}
	var vals int
	var gotErr error
	for _, err := range Pages(context.Background(), fetch) {
		if err != nil {
			gotErr = err
			continue
		}
		vals++
	}
	if vals != 1 || !errors.Is(gotErr, boom) {
		t.Fatalf("vals=%d err=%v", vals, gotErr)
	}
}

func TestRequestOmitsEmptyOperationName(t *testing.T) {
	b, err := json.Marshal(Request{Query: "{ __typename }"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "operationName") {
		t.Fatalf("anonymous request must omit operationName, got %s", b)
	}
	b, err = json.Marshal(Request{OperationName: "Foo", Query: "query Foo { __typename }"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"operationName":"Foo"`) {
		t.Fatalf("named request must carry operationName, got %s", b)
	}
}
