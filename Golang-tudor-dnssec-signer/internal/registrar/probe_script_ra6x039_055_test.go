package registrar

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The diagnostic script must sign exactly the bytes the Go adapter signs
// (RA6X-039) and must keep both credentials out of every child process's
// arguments (RA6X-055). curl and python3 are stubbed on PATH: the curl stub
// records its argv and the config file it was handed; the python3 stub records
// its argv and then runs the real interpreter so the HMAC is still computed.
func TestDynadotProbeScript_SignaturesAndSecretHandling(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "dynadot-probe.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Skipf("probe script not found: %v", err)
	}
	realPython, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	const apiKey = "SYNTHETIC-KEY-a1b2c3"
	const apiSecret = "SYNTHETIC-SECRET-d4e5f6"

	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "argv.log")
	curlOut := filepath.Join(t.TempDir(), "curl.log")
	// curl stub: record argv, dump any -K config file, print a fake response.
	curlStub := "#!/bin/sh\n" +
		"printf 'curl argv:' >> " + log + "\nfor a in \"$@\"; do printf ' [%s]' \"$a\" >> " + log + "; done; printf '\\n' >> " + log + "\n" +
		"while [ $# -gt 0 ]; do if [ \"$1\" = \"-K\" ]; then cat \"$2\" >> " + curlOut + "; fi; shift; done\n" +
		"echo 'HTTP/1.1 200 OK'\n"
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(curlStub), 0755); err != nil {
		t.Fatal(err)
	}
	pyStub := "#!/bin/sh\nprintf 'python3 argv:' >> " + log + "\nfor a in \"$@\"; do printf ' [%s]' \"$a\" >> " + log + "; done; printf '\\n' >> " + log + "\nexec " + realPython + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(pyStub), 0755); err != nil {
		t.Fatal(err)
	}

	c := &DynadotClient{apiKey: apiKey, apiSecret: apiSecret}
	sigRe := regexp.MustCompile(`(?m)^signature:\s+(\S+)`)
	reqIDRe := regexp.MustCompile(`request_id=([0-9a-f-]+)\)`)

	cases := []struct {
		name string
		args []string
		body string
	}{
		{"get (empty body)", []string{"get", "Example.COM"}, ""},
		{"del (empty body)", []string{"del", "example.com"}, ""},
		{"put (json body)", []string{"put", "example.com", "12345", "15", "2", "ABCDEF"}, `{"key_tag":12345,"digest_type":"2","digest":"ABCDEF","algorithm":"15","flags":"","public_key":""}`},
		{"raw body ending in newline", []string{"raw", "PUT", "/restful/v2/domains/example.com/dnssec", "{\"k\":1}\n"}, "{\"k\":1}\n"},
		{"get with request id", []string{"--send-id", "get", "example.com"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Remove(log)
			os.Remove(curlOut)
			cmd := exec.Command("bash", append([]string{script}, tc.args...)...)
			cmd.Env = append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"DYNADOT_API_KEY="+apiKey, "DYNADOT_API_SECRET="+apiSecret)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("script failed: %v\n%s", err, out)
			}
			m := sigRe.FindSubmatch(out)
			if m == nil {
				t.Fatalf("no signature line in output:\n%s", out)
			}
			path := "/restful/v2/domains/example.com/dnssec"
			reqID := ""
			if rm := reqIDRe.FindSubmatch(out); rm != nil {
				reqID = string(rm[1])
			}
			want := c.sign(path, reqID, tc.body)
			if got := string(m[1]); got != want {
				t.Fatalf("script signature %q differs from the Go adapter's %q (request_id %q, body %q)", got, want, reqID, tc.body)
			}

			// Redacted diagnostics show the separator bytes and no secret.
			if strings.Contains(string(out), apiSecret) || strings.Contains(string(out), apiKey) {
				t.Fatal("output must not contain a credential")
			}
			if !strings.Contains(string(out), `<api_key>\n`+path+`\n`) {
				t.Fatalf("redacted string-to-sign must show the exact separators:\n%s", out)
			}

			// No credential in any child's argv; the key reached curl via -K.
			argv, _ := os.ReadFile(log)
			if strings.Contains(string(argv), apiKey) || strings.Contains(string(argv), apiSecret) {
				t.Fatalf("a credential appeared in child-process arguments:\n%s", argv)
			}
			if !strings.Contains(string(argv), "[-K]") {
				t.Fatalf("curl must receive its credentials through a -K config:\n%s", argv)
			}
			cfg, _ := os.ReadFile(curlOut)
			if !strings.Contains(string(cfg), "Authorization: Bearer "+apiKey) {
				t.Fatalf("the curl config must carry the Authorization header, got %q", cfg)
			}
		})
	}
}
