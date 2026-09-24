// SPDX-FileCopyrightText: Copyright The Moby Authors
// SPDX-License-Identifier: Apache-2.0

package apparmor

import (
	"strings"
	"testing"
	"text/template"
)

func TestQuotePeerName(t *testing.T) {
	tests := []struct {
		doc   string
		value string
		want  string
	}{
		{
			doc:  "empty",
			want: "",
		},
		{
			doc:   "simple",
			value: "default-profile",
			want:  `"default-profile"`,
		},
		{
			doc:   "spaces",
			value: "with spaces",
			want:  `"with spaces"`,
		},
		{
			doc:   "double quote",
			value: `foo"bar`,
			want:  `"foo\"bar"`,
		},
		{
			doc:   "backslash",
			value: `foo\bar`,
			want:  `"foo\\bar"`,
		},
		{
			doc:   "escape sequence",
			value: `foo\nbar`,
			want:  `"foo\\nbar"`,
		},
		{
			doc:   "AARE wildcard",
			value: `foo*bar?baz`,
			want:  `"foo\*bar\?baz"`,
		},
		{
			doc:   "AARE character class",
			value: `foo[bar]`,
			want:  `"foo\[bar\]"`,
		},
		{
			doc:   "AARE alternation",
			value: `foo{bar,baz}`,
			want:  `"foo\{bar\,baz\}"`,
		},
		{
			doc:   "AARE anchor",
			value: `foo^bar`,
			want:  `"foo\^bar"`,
		},
		{
			doc:   "invalid UTF-8 with special character",
			value: "foo\xff*bar",
			want:  "\"foo\xff\\*bar\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.doc, func(t *testing.T) {
			if got := quotePeerName(tc.value); got != tc.want {
				t.Errorf("quotePeerName(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestTemplateProfileNames(t *testing.T) {
	data := profileData{
		name:          `foo"bar,*?[ab]{c,d}^\baz`,
		daemonProfile: `daemon,profile\baz`,
	}
	tmpl, err := template.New("profile").Parse(baseTemplate)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := tmpl.Execute(&out, data); err != nil {
		t.Fatal(err)
	}

	// Declarations retain AARE escapes, while peer patterns consume them.
	for _, want := range []string{
		`profile "foo\"bar,*?[ab]{c,d}^\baz" flags=(attach_disconnected,mediate_deleted) {`,
		`  signal (receive) peer="daemon\,profile\\baz",`,
		`  signal (send,receive) peer="foo\"bar\,\*\?\[ab\]\{c\,d\}\^\\baz",`,
		`  ptrace (trace,tracedby,read,readby) peer="foo\"bar\,\*\?\[ab\]\{c\,d\}\^\\baz",`,
	} {
		if !strings.Contains(out.String(), "\n"+want+"\n") {
			t.Errorf("generated profile is missing line %q", want)
		}
	}
}
