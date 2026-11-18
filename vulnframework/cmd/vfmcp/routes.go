package main

import "strings"

// routeInventory is every API route the connector can reach, written as the
// published contract writes them (internal/api/openapi.go). Each is a read.
//
// The client refuses any path that matches none of these (VM-F-1102), and
// TestRouteInventoryIsReadsOnly checks each against the live OpenAPI document:
// every entry must exist there with a GET operation. Adding a write here would
// fail that test, and calling one would fail the transport.
var routeInventory = []string{
	"/v1/health",
	"/v1/findings",
	"/v1/findings/{fp}",
	"/v1/findings/{fp}/timeline",
	"/v1/repos",
	"/v1/repos/{repo}",
	"/v1/repos/{repo}/nuguard",
	"/v1/runs",
	"/v1/runs/compare",
	"/v1/runs/{id}",
	"/v1/coverage",
	"/v1/nuguard",
}

// matchRoute reports which inventory route path is an instance of.
//
// {repo} is owner/name, two segments; every other parameter is one. Literal
// segments win over parameters, so /v1/runs/compare is never read as a run
// identifier.
func matchRoute(path string) (string, bool) {
	if strings.ContainsAny(path, "?#") {
		return "", false
	}
	got := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, r := range routeInventory {
		if literalMatch(r, got) {
			return r, true
		}
	}
	for _, r := range routeInventory {
		if paramMatch(r, got) {
			return r, true
		}
	}
	return "", false
}

func literalMatch(route string, got []string) bool {
	want := strings.Split(strings.TrimPrefix(route, "/"), "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

func paramMatch(route string, got []string) bool {
	want := strings.Split(strings.TrimPrefix(route, "/"), "/")
	j := 0
	for _, w := range want {
		switch {
		case w == "{repo}":
			if j+2 > len(got) || got[j] == "" || got[j+1] == "" {
				return false
			}
			j += 2
		case strings.HasPrefix(w, "{"):
			if j >= len(got) || got[j] == "" {
				return false
			}
			j++
		default:
			if j >= len(got) || got[j] != w {
				return false
			}
			j++
		}
	}
	return j == len(got)
}
