// Package jsonapi implements the subset of JSON:API 1.0 that ButterflyMX's
// /v3 API uses: lenient document decoding, a (type, id) keyed resource index
// for resolving relationships against "included", pagination links, and
// request-body builders.
//
// Decoding ignores unknown members and treats unresolvable relationship
// references as soft misses. Request building can emit explicit nulls, both
// in attributes and in relationships, because the official app sends them.
package jsonapi
