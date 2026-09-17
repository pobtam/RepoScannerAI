package audit

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// FieldPath is a dotted path to one schema field, for example
// "Classification.FirstPartyPath".
type FieldPath string

// Fields enumerates every leaf field of a struct type, recursively.
//
// Leaves rather than structs, because a struct that is non-zero tells you
// nothing: `Classification` is populated the moment any one of its eight
// fields is, and the seven that are not would hide behind it. The whole point
// of this audit is that the granularity has to be the field a consumer reads.
func Fields(t reflect.Type) []FieldPath {
	var out []FieldPath
	walk(t, "", &out, map[reflect.Type]bool{})
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func walk(t reflect.Type, prefix string, out *[]FieldPath, seen map[reflect.Type]bool) {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	// Recursion guard: a self-referential type would otherwise never
	// terminate, and the audit must not hang on a schema change.
	if seen[t] {
		return
	}
	seen[t] = true
	defer delete(seen, t)

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			// Unexported: not part of the schema any consumer can read.
			continue
		}
		name := prefix + f.Name

		ft := f.Type
		for ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		// A struct is descended into; everything else — including slices and
		// maps, whose emptiness is the thing worth detecting — is a leaf.
		if ft.Kind() == reflect.Struct && !isTimeLike(ft) {
			walk(ft, name+".", out, seen)
			continue
		}
		*out = append(*out, FieldPath(name))
	}
}

// isTimeLike reports types treated as leaves despite being structs.
func isTimeLike(t reflect.Type) bool {
	return t.PkgPath() == "time" && t.Name() == "Time"
}

// Populated returns the leaf fields of v that hold a non-zero value.
//
// Non-zero is the test, and it is imperfect in one direction on purpose: a
// producer that writes the zero value — false, 0, "" — is indistinguishable
// from one that writes nothing. Those fields are handled by exemption with a
// named producer rather than by pretending the check covers them, because a
// looser check that appeared to cover them would be worse than an honest gap.
func Populated(v any) map[FieldPath]bool {
	out := map[FieldPath]bool{}
	collect(reflect.ValueOf(v), "", out, map[reflect.Type]bool{})
	return out
}

func collect(v reflect.Value, prefix string, out map[FieldPath]bool, seen map[reflect.Type]bool) {
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	if seen[t] {
		return
	}
	seen[t] = true
	defer delete(seen, t)

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		name := prefix + f.Name
		fv := v.Field(i)

		ft := f.Type
		for ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && !isTimeLike(ft) {
			collect(fv, name+".", out, seen)
			continue
		}
		if !fv.IsZero() {
			out[FieldPath(name)] = true
		}
	}
}

// Exemption records a field no producer in the audit writes, and what does.
//
// It is a claim, not a dismissal. Naming the producer is what makes an
// exemption reviewable: "written by internal/score" can be checked, and
// "not applicable" cannot.
type Exemption struct {
	// Producer names what writes this field. Required.
	Producer string
	// Why explains it where the producer's name alone is not enough.
	Why string
}

// Census is the result of running the real producers.
type Census struct {
	// Schema is every field the type declares.
	Schema []FieldPath
	// Written is what the producers actually populated.
	Written map[FieldPath]bool
	// Exempt is the reviewed set, keyed by field.
	Exempt map[FieldPath]Exemption
}

// Unwritten returns the fields nobody writes and nobody has accounted for.
//
// These are the defect. Each is a consumer reading something that is always
// empty in production, and each will be invisible to every test that supplies
// the field itself.
func (c Census) Unwritten() []FieldPath {
	var out []FieldPath
	for _, f := range c.Schema {
		if c.Written[f] {
			continue
		}
		if _, ok := c.Exempt[f]; ok {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// StaleExemptions returns exemptions for fields the producers do write.
//
// Reported because an exemption that is no longer true is a comment asserting
// something false about the system, and the next person to read it will
// believe it. It is also how an exemption stops being load-bearing without
// anyone noticing.
func (c Census) StaleExemptions() []FieldPath {
	var out []FieldPath
	for f := range c.Exempt {
		if c.Written[f] {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// UnknownExemptions returns exemptions naming fields the schema does not have.
//
// A schema field that is renamed or removed leaves its exemption behind,
// silently exempting nothing while appearing to account for something.
func (c Census) UnknownExemptions() []FieldPath {
	inSchema := make(map[FieldPath]bool, len(c.Schema))
	for _, f := range c.Schema {
		inSchema[f] = true
	}
	var out []FieldPath
	for f := range c.Exempt {
		if !inSchema[f] {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Report renders the census for a failing test.
func (c Census) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d schema fields, %d written by a real producer, %d exempt\n",
		len(c.Schema), len(c.Written), len(c.Exempt))
	if un := c.Unwritten(); len(un) > 0 {
		b.WriteString("\nNO PRODUCER WRITES:\n")
		for _, f := range un {
			fmt.Fprintf(&b, "  %s\n", f)
		}
	}
	if stale := c.StaleExemptions(); len(stale) > 0 {
		b.WriteString("\nEXEMPT BUT ACTUALLY WRITTEN (remove the exemption):\n")
		for _, f := range stale {
			fmt.Fprintf(&b, "  %s — claimed to be written by %s\n", f, c.Exempt[f].Producer)
		}
	}
	if unknown := c.UnknownExemptions(); len(unknown) > 0 {
		b.WriteString("\nEXEMPT BUT NOT IN THE SCHEMA (renamed or removed):\n")
		for _, f := range unknown {
			fmt.Fprintf(&b, "  %s\n", f)
		}
	}
	return b.String()
}
