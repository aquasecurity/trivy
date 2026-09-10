package parser

import (
	"reflect"
	"testing"
)

func TestDropShadowedTerraformFiles(t *testing.T) {
	cases := []struct {
		name  string
		in    []string
		want  []string
	}{
		{"tofu shadows tf", []string{"dir/main.tf", "dir/main.tofu"}, []string{"dir/main.tofu"}},
		{"tofu.json shadows tf.json", []string{"dir/main.tf.json", "dir/main.tofu.json"}, []string{"dir/main.tofu.json"}},
		{"no cross-extension shadow", []string{"dir/main.tofu", "dir/main.tf.json"}, []string{"dir/main.tofu", "dir/main.tf.json"}},
		{"tf alone kept", []string{"dir/main.tf"}, []string{"dir/main.tf"}},
		{"unrelated files kept", []string{"dir/a.tf", "dir/b.tofu", "dir/c.txt"}, []string{"dir/a.tf", "dir/b.tofu", "dir/c.txt"}},
	}
	for _, c := range cases {
		got := dropShadowedTerraformFiles(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
