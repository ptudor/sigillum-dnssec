#!/usr/bin/env bash
# dynadot-probe.sh — exercise the Dynadot restful/v2 DNSSEC endpoints with the
# exact same wire format the Go adapter uses (registrar_dynadot.go), so we can
# tell whether a "X-Signature invalid" / "Bad Request" / etc. is our side or
# Dynadot's. Every request prints:
#   - the full path
#   - the request body (the actual bytes signed)
#   - the string-to-sign (apiKey "\n" path "\n" requestID "\n" body)
#   - the computed X-Signature (base64 HMAC-SHA256)
#   - the curl command flags
#   - response status + headers + body
#
# Usage:
#   DYNADOT_API_KEY=... DYNADOT_API_SECRET=... \
#     scripts/dynadot-probe.sh get  example.com
#   scripts/dynadot-probe.sh put  example.com 12345 15 2 ABCDEF...
#   scripts/dynadot-probe.sh del  example.com
#   scripts/dynadot-probe.sh raw  PUT /restful/v2/domains/example.com/dnssec '{...}'
#
# Flags (before the subcommand):
#   --prod           Hit api.dynadot.com instead of api-sandbox.dynadot.com
#   --send-id        Send X-Request-ID header (and sign with it). Default off,
#                    matching the Go adapter's send_request_id=false default.
#   --variant=NAME   For put: alternate body shapes for probing.
#                    snake-empty    default; snake_case, all 6 fields, flags+public_key=""
#                    snake-omit     snake_case, omit flags + public_key entirely
#                    camel-empty    camelCase, all 6 fields, flags+publicKey=""
#                    keytag-string  key_tag serialized as string instead of int
#                    labeled        algorithm/digest_type as "NAME (N)" — matches the
#                                   shape Dynadot's GET returns. Useful to test whether
#                                   PUT requires the same labeled form.
#                    numeric        algorithm/digest_type as raw JSON numbers (no quotes)
#                                   — tests the literal "Integer" reading of the docs.
#                    minimal        snake_case, only the 4 DS-form fields (no flags,
#                                   no public_key). Stricter than snake-omit because
#                                   it shows the call site's intent: this is a DS, not
#                                   a DNSKEY-form set_dnssec request.
#
# Requires: bash 3.2+, curl, python3 (HMAC via a protected descriptor) or
# openssl (fallback; see hmac_b64), awk.
#
# Secrets never appear in child-process arguments (RA6X-055): the HMAC key is
# handed to python3 on a private file descriptor, and the Authorization header
# reaches curl through a config file on a private descriptor (`-K`). Shell
# tracing is disabled around every secret-handling step so `bash -x` cannot
# echo an expanded secret. The bytes signed are built with `printf -v`, which
# keeps trailing newline separators that command substitution would strip
# (RA6X-039), so GET/DELETE (empty body) sign exactly what the Go adapter signs.

set -euo pipefail

API_KEY="${DYNADOT_API_KEY:-}"
API_SECRET="${DYNADOT_API_SECRET:-}"
HOST="https://api-sandbox.dynadot.com"
SEND_ID=0
VARIANT="snake-empty"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prod)        HOST="https://api.dynadot.com"; shift ;;
    --send-id)     SEND_ID=1; shift ;;
    --variant=*)   VARIANT="${1#*=}"; shift ;;
    -h|--help)     sed -n '2,30p' "$0"; exit 0 ;;
    *)             break ;;
  esac
done

if [[ -z "$API_KEY" || -z "$API_SECRET" ]]; then
  echo "ERROR: DYNADOT_API_KEY and DYNADOT_API_SECRET must be set." >&2
  exit 64
fi

# uuid4 — used for X-Request-ID when --send-id is set.
gen_uuid() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import uuid; print(uuid.uuid4())'
  else
    # Pure-bash fallback. Bytes from /dev/urandom, format a v4 UUID.
    local b
    b=$(LC_ALL=C tr -dc '0-9a-f' </dev/urandom | head -c 32)
    printf '%s-%s-4%s-%s%s-%s\n' \
      "${b:0:8}" "${b:8:4}" "${b:13:3}" \
      "${b:16:1}" "${b:17:3}" "${b:20:12}"
  fi
}

# hmac_b64 STRING_TO_SIGN — emits base64(HMAC-SHA256(secret, STRING_TO_SIGN)).
# The secret is passed to python3 on file descriptor 3 (a pipe from process
# substitution), never as an argument. openssl's `dgst -hmac` can only take the
# key as an argument, so it is used only when python3 is absent, with a warning
# about the exposure. The message is written on stdin so trailing newline bytes
# survive intact.
hmac_b64() {
  { set +x; } 2>/dev/null
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -c '
import base64, hashlib, hmac, os, sys
secret = os.fdopen(3, "rb").read()
msg = sys.stdin.buffer.read()
sys.stdout.write(base64.b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).decode())
' 3< <(printf '%s' "$API_SECRET")
  else
    echo "warning: python3 not found; falling back to openssl, which exposes the HMAC secret in its process arguments" >&2
    printf '%s' "$1" | openssl dgst -sha256 -hmac "$API_SECRET" -binary | openssl base64 -A
  fi
}

# build_body_put KEY_TAG ALG DIGEST_TYPE DIGEST  — selects shape by $VARIANT.
# All snake-* variants put fields in the order the Go struct declares:
#   key_tag, digest_type, digest, algorithm, flags, public_key.
build_body_put() {
  local kt="$1" alg="$2" dt="$3" dig="$4"
  case "$VARIANT" in
    snake-empty)
      printf '{"key_tag":%s,"digest_type":"%s","digest":"%s","algorithm":"%s","flags":"","public_key":""}' \
        "$kt" "$dt" "$dig" "$alg" ;;
    snake-omit)
      printf '{"key_tag":%s,"digest_type":"%s","digest":"%s","algorithm":"%s"}' \
        "$kt" "$dt" "$dig" "$alg" ;;
    camel-empty)
      printf '{"keyTag":%s,"digestType":"%s","digest":"%s","algorithm":"%s","flags":"","publicKey":""}' \
        "$kt" "$dt" "$dig" "$alg" ;;
    keytag-string)
      printf '{"key_tag":"%s","digest_type":"%s","digest":"%s","algorithm":"%s","flags":"","public_key":""}' \
        "$kt" "$dt" "$dig" "$alg" ;;
    labeled)
      # Mirrors the "NAME (N)" shape Dynadot's GET returns. Map common
      # algorithm/digest_type numbers back to the labeled form. Falls
      # back to bare numerics for anything not listed.
      local alg_label="$alg" dt_label="$dt"
      case "$alg" in
        13) alg_label="ECDSAP256SHA256 (13)" ;;
        14) alg_label="ECDSAP384SHA384 (14)" ;;
        15) alg_label="ED25519 (15)" ;;
        16) alg_label="ED448 (16)" ;;
      esac
      case "$dt" in
        2) dt_label="SHA-256 (2)" ;;
        4) dt_label="SHA-384 (4)" ;;
      esac
      printf '{"key_tag":%s,"digest_type":"%s","digest":"%s","algorithm":"%s","flags":"","public_key":""}' \
        "$kt" "$dt_label" "$dig" "$alg_label" ;;
    numeric)
      printf '{"key_tag":%s,"digest_type":%s,"digest":"%s","algorithm":%s}' \
        "$kt" "$dt" "$dig" "$alg" ;;
    minimal)
      printf '{"key_tag":%s,"digest_type":"%s","digest":"%s","algorithm":"%s"}' \
        "$kt" "$dt" "$dig" "$alg" ;;
    *) echo "unknown --variant $VARIANT" >&2; exit 64 ;;
  esac
}

# call METHOD PATH BODY  — body may be the empty string for GET/DELETE.
call() {
  local method="$1" path="$2" body="$3"

  local req_id=""
  if [[ "$SEND_ID" -eq 1 ]]; then
    req_id="$(gen_uuid)"
  fi

  # The Go adapter signs apiKey "\n" fullPathAndQuery "\n" requestID "\n" body
  # (for /dnssec there is no query). Built with printf -v: command substitution
  # would strip the trailing newline separators of an empty request ID and an
  # empty body, so GET/DELETE would sign different bytes than the adapter
  # (RA6X-039).
  local string_to_sign
  printf -v string_to_sign '%s\n%s\n%s\n%s' "$API_KEY" "$path" "$req_id" "$body"
  local sig
  sig=$(hmac_b64 "$string_to_sign")

  echo "----- request -----"
  echo "host:       $HOST"
  echo "method:     $method"
  echo "path:       $path"
  echo "send_id:    $SEND_ID    (request_id=${req_id:-<empty>})"
  echo "variant:    $VARIANT"
  echo "body bytes: ${#body}"
  if [[ -n "$body" ]]; then echo "body:       $body"; fi
  # Redact the api key (the first line of string_to_sign) so this output is safe
  # to paste into a bug report. The real key still goes into the HMAC above and
  # the Authorization header below.
  local redacted_sts
  printf -v redacted_sts '%s\n%s\n%s\n%s' "<api_key>" "$path" "$req_id" "$body"
  echo "string_to_sign (api key redacted; each newline shown as \\n, exactly the bytes signed):"
  printf '  %s\n' "${redacted_sts//$'\n'/\\n}"
  echo "signature:  $sig"
  echo

  # The Authorization header goes to curl through a config file on a private
  # descriptor rather than an argument (RA6X-055); everything else is plain argv.
  local -a curl_args=(
    -sS -i
    -X "$method"
    -H "Accept: application/json"
    -H "X-Signature: $sig"
    -H "User-Agent: dynadot-probe/1.0"
  )
  if [[ -n "$body" ]]; then
    curl_args+=(-H "Content-Type: application/json" --data-raw "$body")
  fi
  if [[ "$SEND_ID" -eq 1 ]]; then
    curl_args+=(-H "X-Request-ID: $req_id")
  fi

  echo "----- response -----"
  { set +x; } 2>/dev/null
  curl -K <(printf 'header = "Authorization: Bearer %s"\n' "$API_KEY") "${curl_args[@]}" "$HOST$path"
  echo
  echo
}

dnssec_path() {
  # Lowercase + strip trailing dot, matching dnssecPath() in the Go adapter.
  # Use tr (not the bash-4 ${var,,}) so this runs on macOS's default bash 3.2.
  local d
  d=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  d="${d%.}"
  printf '/restful/v2/domains/%s/dnssec' "$d"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  get)
    domain="${1:?domain required}"
    call GET "$(dnssec_path "$domain")" ""
    ;;
  put)
    domain="${1:?domain}"; kt="${2:?key_tag}"; alg="${3:?algorithm (numeric)}"
    dt="${4:?digest_type (2 or 4)}"; dig="${5:?digest hex}"
    body=$(build_body_put "$kt" "$alg" "$dt" "$dig")
    call PUT "$(dnssec_path "$domain")" "$body"
    ;;
  del|delete|clear)
    domain="${1:?domain required}"
    call DELETE "$(dnssec_path "$domain")" ""
    ;;
  raw)
    method="${1:?method}"; path="${2:?path}"; body="${3:-}"
    call "$method" "$path" "$body"
    ;;
  ""|-h|--help)
    sed -n '2,30p' "$0"
    ;;
  *)
    echo "unknown subcommand: $cmd" >&2
    exit 64
    ;;
esac
