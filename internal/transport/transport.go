// Package transport is the one place that talks to the zcode start-plan
// gateway.
//
// The lane, verified live 2026-10-30 against a running account:
//
//	POST https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages
//	Authorization: Bearer <plan JWT>
//	+ the client's identity headers (identity LLM face)
//	+ the client's 3-block identity system prompt (systemprompt)
//	-> 200 text/event-stream, GLM-5.3 / GLM-5.3-Flash on plan quota.
//
// What this lane does NOT use (each tried, each wrong):
//   - the V4 signing handshake (X-Client-Sig/X-Client-Pow/X-App-Id). Signed
//     requests authenticate but land on the paid lane and answer
//     `429 1113 "Insufficient balance or no resource package"` even with a
//     plan balance.
//   - X-Zcode-Authorization: injected by the client only under
//     /api/v1/ultra*; on this path the bearer itself is the plan JWT.
//   - x-api-key: the desktop client mirrors the JWT into it, the gateway
//     ignores it — omitting it is fine.
//
// The gateway also content-inspects the `system` field: a request without
// the exact identity blocks is refused with `405 {"code":3012}` ("unusual
// activity") regardless of headers — the 3012 is a prompt-shape rejection,
// not only an abuse one.
package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"os"
	"sync"
	"time"

	"github.com/apissaj/zcode-gateway/internal/accounts"
	"github.com/apissaj/zcode-gateway/internal/auth"
	"github.com/apissaj/zcode-gateway/internal/identity"
	"github.com/apissaj/zcode-gateway/internal/systemprompt"
)

// InferenceOrigin and PlanAnthropicPath locate the plan lane.
var (
	InferenceOrigin   = envOr("ZCODE_INFERENCE_ORIGIN", "https://zcode.z.ai")
	PlanAnthropicPath = "/api/v1/zcode-plan/anthropic/v1/messages"
)

// UpstreamError carries the gateway's status/code to the client dialect.
type UpstreamError struct {
	Msg           string
	Status        int
	Body          any
	Kind          string // upstream | config | protocol
	Code          any    // gateway envelope code (3012/1113/3008/3009/3001)
	LogID         string // upstream logid, kept for tracing/support tickets
	AccountSwitch bool   // internal: rotation may continue with another account
}

func (e *UpstreamError) Error() string { return e.Msg }

// HTTPStatus maps the error onto a status a downstream router can act on. The
// plan lane reports capacity/quota failures inside a 200 body, so the upstream
// status alone is unusable: capacity codes must stay retryable and a
// 200-with-error must never reach the client as success.
func (e *UpstreamError) HTTPStatus() int {
	switch {
	case codeIs(e.Code, 1005): // allowance exhausted / not entitled right now
		return http.StatusTooManyRequests
	case codeIs(e.Code, 3008): // account slot parked by the desktop client
		return http.StatusTooManyRequests
	case codeIs(e.Code, 3009): // model concurrency, retry shortly
		return http.StatusTooManyRequests
	case codeIs(e.Code, 3012): // blocked, wait a minute and retry
		return http.StatusTooManyRequests
	case codeIs(e.Code, 1113): // this account's allowance is spent (already 429 upstream)
		return http.StatusTooManyRequests
	}
	if e.Status >= 400 && e.Status <= 599 {
		return e.Status
	}
	return http.StatusBadGateway
}

// RetryAfterSeconds suggests a wait for retryable statuses (0: emit no header).
func (e *UpstreamError) RetryAfterSeconds() int {
	switch {
	case codeIs(e.Code, 3012), codeIs(e.Code, 1005), codeIs(e.Code, 1113):
		return 60
	case codeIs(e.Code, 3008), codeIs(e.Code, 3009):
		return 2
	}
	if e.Status == http.StatusTooManyRequests {
		return 2
	}
	return 0
}


func envOr(key, fallback string) string {
	if v := strings.TrimSpace(osGetenv(key)); v != "" {
		return v
	}
	return fallback
}

// errorFromResponse maps the gateway's {code,msg,logid} envelope onto an
// UpstreamError with a human message per known code.
func errorFromResponse(status int, body []byte) *UpstreamError {
	var env struct {
		Code  any    `json:"code"`
		Msg   string `json:"msg"`
		LogID string `json:"logid"`
		Error *struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
		Raw string `json:"-"`
	}
	text := string(body)
	if json.Unmarshal(body, &env) != nil {
		env.Raw = text
	}
	code := env.Code
	message := ""
	switch code {
	case float64(3012):
		message = "zcode gateway blocked this request (3012). The system prompt must carry the exact ZCode identity blocks and the session must look like a real client. If this account was just very active, wait a minute and retry."
	case float64(1113):
		message = "zcode paid lane answered \"insufficient balance\" (1113): the request was not recognized as start-plan traffic."
	case float64(3009):
		message = fmt.Sprintf("model concurrency limit (3009)%s - retry shortly", msgSuffix(env.Msg))
	case float64(3008):
		message = fmt.Sprintf("account concurrency limit (3008)%s - the desktop client is busy on this account; retry shortly", msgSuffix(env.Msg))
	case float64(3001):
		message = fmt.Sprintf("gateway parameter error (3001)%s", msgSuffix(env.Msg))
	default:
		if env.Error != nil && env.Error.Message != "" {
			message = env.Error.Message
		} else {
			message = fmt.Sprintf("upstream %d", status)
		}
	}
	return &UpstreamError{Msg: message, Status: status, Body: env, Kind: "upstream", Code: code, LogID: env.LogID}
}

// BodyErrorEnvelope reports a gateway error carried inside a 2xx body. The plan
// lane answers quota/capacity failures with HTTP 200 plus a
// {"code":...,"msg":...,"logid":...} envelope, so the status alone cannot be
// trusted. Returns nil for a normal payload.
func BodyErrorEnvelope(status int, body []byte) *UpstreamError {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var probe struct {
		Code  any             `json:"code"`
		Type  string          `json:"type"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(trimmed, &probe) != nil {
		return nil
	}
	if probe.Code != nil {
		if codeIs(probe.Code, 0) {
			return nil // {"code":0,...} is a success envelope
		}
		return errorFromResponse(status, trimmed)
	}
	// No code: only treat it as an error when the body is not a normal
	// Anthropic message (which always carries "type":"message").
	if len(probe.Error) > 0 && (probe.Type == "" || probe.Type == "error") {
		return errorFromResponse(status, trimmed)
	}
	return nil
}

// sniffBodyError peeks a non-streaming 2xx body for an error envelope and
// returns the bytes to replay, so the caller can still consume the response.
func sniffBodyError(res *http.Response) (*UpstreamError, []byte) {
	if res == nil || res.Body == nil {
		return nil, nil
	}
	if strings.Contains(strings.ToLower(res.Header.Get("Content-Type")), "event-stream") {
		return nil, nil // streamed: the server peeks the first SSE event instead
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	res.Body.Close()
	if err != nil {
		return &UpstreamError{Msg: "upstream body read failed: " + err.Error(), Status: http.StatusBadGateway, Kind: "upstream"}, nil
	}
	if ue := BodyErrorEnvelope(res.StatusCode, raw); ue != nil {
		return ue, nil
	}
	return nil, raw
}

func msgSuffix(msg string) string {
	if strings.TrimSpace(msg) == "" {
		return ""
	}
	return ": " + msg
}

// isTransient reports gateway responses worth retrying in place: model
// concurrency, 429, 5xx. Account-wide failures are switchable instead.
func isTransient(err *UpstreamError) bool {
	if err == nil {
		return false
	}
	if codeIs(err.Code, 3009) {
		return true
	}
	if err.Status == http.StatusTooManyRequests || err.Status >= 500 {
		return true
	}
	return false
}

// isSwitchable reports errors that justify rotating to the next account:
// this credential's allowance is spent, it is rejected, or its user slot is
// parked by the desktop client. Anything else (model concurrency 3009, 5xx,
// transport) is global-ish and gets retried in place instead.
func isSwitchable(err *UpstreamError, status int) bool {
	if err == nil {
		return false
	}
	if codeIs(err.Code, 1113) || codeIs(err.Code, 3008) {
		return true
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return true
	}
	if status == http.StatusTooManyRequests && !codeIs(err.Code, 3009) {
		return true
	}
	return false
}

// codeIs compares a gateway envelope code against a number, tolerating the
// shapes JSON decoders hand back (float64/float32/int/int64/json.Number/string).
func codeIs(code any, want float64) bool {
	switch v := code.(type) {
	case float64:
		return v == want
	case float32:
		return float64(v) == want
	case int:
		return float64(v) == want
	case int64:
		return float64(v) == want
	case json.Number:
		f, err := v.Float64()
		return err == nil && f == want
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return err == nil && f == want
	}
	return false
}

// candidate is one account attempt for a request.
type candidate struct {
	ID          string // "" for the legacy/env single account
	Label       string
	JWT         string
	DeviceID    string
	SessionSeed string
	UserID      string
}

// legacyUserID extracts the account uuid from a JWT's user_id claim.
func legacyUserID(jwt string) string {
	claims, ok := auth.DecodeJWT(jwt)
	if !ok {
		return ""
	}
	if v, _ := claims["user_id"].(string); v != "" {
		return v
	}
	v, _ := claims["sub"].(string)
	return v
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Candidates resolves the accounts one request may try, in order: an
// explicit JWT wins; then a pinned account; then the stored ring; then the
// single-token fallbacks. Empty result = no credential at all.
func Candidates(jwt, accountID string) ([]candidate, error) {
	if strings.TrimSpace(jwt) != "" {
		mid := identity.ResolveDeviceMid()
		if mid == "" {
			mid = newUUID()
		}
		return []candidate{{JWT: jwt, DeviceID: mid, UserID: legacyUserID(jwt)}}, nil
	}
	if accountID != "" {
		for _, a := range accounts.List() {
			if a.ID == accountID {
				return []candidate{{ID: a.ID, Label: a.Label, JWT: a.JWT, DeviceID: a.DeviceID, SessionSeed: a.SessionSeed, UserID: a.UserID}}, nil
			}
		}
	}
	if stored := accounts.Usable(nil); len(stored) > 0 {
		out := make([]candidate, 0, len(stored))
		for _, a := range stored {
			out = append(out, candidate{ID: a.ID, Label: a.Label, JWT: a.JWT, DeviceID: a.DeviceID, SessionSeed: a.SessionSeed, UserID: a.UserID})
		}
		return out, nil
	}
	legacy := auth.ResolvePlanJWT("")
	if legacy == "" {
		return nil, &UpstreamError{
			Msg:    "No zcode plan JWT available. Run: zcode-gateway login (or keep the desktop client signed in, or set ZCODE_PLAN_JWT)",
			Status: 500, Kind: "config",
		}
	}
	mid := identity.ResolveDeviceMid()
	if mid == "" {
		mid = newUUID()
	}
	return []candidate{{JWT: legacy, DeviceID: mid, SessionSeed: osGetenv("ZCODE_SESSION_SEED"), Label: "default", UserID: legacyUserID(legacy)}}, nil
}

// ShapePlanBody shapes one Anthropic-format body for the plan gateway:
// canonical identity system blocks with the client's own system prompt
// riding block 3, session metadata, and sane sampling defaults.
func ShapePlanBody(body map[string]any, sessionID, deviceID, accountUUID string) (map[string]any, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	out["system"] = systemprompt.BuildSystem(body["system"])
	meta, _ := out["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta["user_id"] = systemprompt.MetadataUserID(deviceID, sessionID, accountUUID)
	out["metadata"] = meta
	if out["max_tokens"] == nil {
		out["max_tokens"] = 8192
	}
	if out["thinking"] == nil && systemprompt.ForceThinking() {
		out["thinking"] = map[string]any{"type": "enabled"}
	}
	return out, nil
}

var (
	laneMu  sync.Mutex
	laneSem chan struct{}
	laneWg  sync.WaitGroup
)

func laneSlot() chan struct{} {
	laneOnce.Do(func() {
		width := 1
		if v := osGetenv("ZCODE_LANE_WIDTH"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				width = n
			}
		}
		laneSem = make(chan struct{}, width)
	})
	return laneSem
}

var laneOnce sync.Once

// WithLane serializes inference calls through one lane (the gateway enforces
// a per-account in-flight limit shared with the desktop client: 429 3008
// user / 3009 model), so concurrent bridge clients queue instead of
// collectively tripping the limit.
func WithLane(ctx context.Context, fn func() error) error {
	laneWg.Add(1)
	defer laneWg.Done()
	select {
	case laneSlot() <- struct{}{}:
		defer func() { <-laneSlot() }()
		return fn()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SendOpts carries one upstream call's parameters.
type SendOpts struct {
	Body            map[string]any // Anthropic-format request
	JWT             string         // explicit token override (skips accounts)
	AccountID       string         // pin to one stored account
	ClientSessionID string         // conversation affinity key
	Context         context.Context
	HTTP            *http.Client
	UpstreamTimeout time.Duration // hard deadline (0: 5m)
}

// SendAnthropic sends one Anthropic-shaped request to the plan endpoint
// through the shared lane, rotating across stored accounts when a switchable
// error fires (allowance 1113/429, auth 401/403, account concurrency 3008).
// Each account gets its own transient retry budget (3009/5xx/network) first;
// failures cool that account down so the next request starts elsewhere. With
// a single account (or the legacy desktop/env token) the behavior matches
// the original plan-lane shape. The response body is NOT consumed here.
func SendAnthropic(o SendOpts) (*http.Response, error) {
	ctx := o.Context
	if ctx == nil {
		ctx = context.Background()
	}
	cands, err := Candidates(o.JWT, o.AccountID)
	if err != nil {
		return nil, err
	}
	timeout := o.UpstreamTimeout
	if timeout <= 0 {
		// ZCODE_UPSTREAM_TIMEOUT_MS hard-deadline override; default 5m.
		if v := osGetenv("ZCODE_UPSTREAM_TIMEOUT_MS"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				timeout = time.Duration(n) * time.Millisecond
			}
		}
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}
	}
	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	var lastErr *UpstreamError
	tried := map[string]bool{}
	for attempt := 0; ; attempt++ {
		var acct *candidate
		for i := range cands {
			key := cands[i].ID
			if key == "" {
				key = fmt.Sprintf("legacy#%d", i)
			}
			if !tried[key] {
				acct = &cands[i]
				tried[key] = true
				break
			}
		}
		if acct == nil {
			break
		}
		res, err := runAccount(ctx, client, *acct, o, timeout)
		if err == nil {
			if acct.ID != "" {
				accounts.ClearCooldown(acct.ID)
			}
			return res, nil
		}
		ue, ok := err.(*UpstreamError)
		if !ok {
			ue = &UpstreamError{Msg: err.Error(), Status: 502, Kind: "upstream"}
		}
		lastErr = ue
		if !ue.AccountSwitch {
			return nil, ue // global failure: no point switching
		}
		if acct.ID != "" {
			switch {
			case ue.Status == 401 || ue.Status == 403:
				accounts.MarkReauth(acct.ID)
			case ue.Code == float64(1113) || ue.Status == http.StatusTooManyRequests:
				accounts.MarkCooldown(acct.ID, 0)
			default:
				accounts.MarkCooldown(acct.ID, 2*time.Minute)
			}
		}
		_ = attempt
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &UpstreamError{Msg: "no usable zcode account", Status: 502, Kind: "config"}
}

// runAccount runs one account's turn: transient retries in place, one
// refresh on 401, then a switchable error => throw for rotation.
func runAccount(ctx context.Context, client *http.Client, acct candidate, o SendOpts, timeout time.Duration) (*http.Response, error) {
	maxAttempts := 3
	if v := osGetenv("ZCODE_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxAttempts = n
		}
	}
	baseMs := 1500
	if v := osGetenv("ZCODE_RETRY_BASE_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			baseMs = n
		}
	}
	bearer := acct.JWT
	refreshed := false
	var lastErr *UpstreamError
	for n := 0; n < maxAttempts; n++ {
		res, attemptErr := attemptOnce(ctx, client, acct, bearer, o, timeout)
		if res != nil && res.StatusCode >= 200 && res.StatusCode < 300 {
			// A 2xx body can still be a gateway error envelope (the plan lane
			// reports capacity/quota failures that way), so peek before
			// declaring success: transient codes must retry in place and
			// capacity codes must reach the caller as a retryable status.
			ue, replay := sniffBodyError(res)
			if ue == nil {
				if replay != nil {
					res.Body = io.NopCloser(bytes.NewReader(replay))
				}
				return res, nil
			}
			lastErr = ue
			if isSwitchable(lastErr, lastErr.Status) {
				lastErr.AccountSwitch = true
			}
		} else if attemptErr != nil {
			if ctx.Err() != nil {
				return nil, attemptErr // client hung up or deadline
			}
			if ue, ok := attemptErr.(*UpstreamError); ok {
				lastErr = ue
			} else {
				lastErr = &UpstreamError{Msg: attemptErr.Error(), Status: 502, Kind: "upstream"}
			}
		} else {
			body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
			res.Body.Close()
			lastErr = errorFromResponse(res.StatusCode, body)
			// Re-arm the switchable flag for this turn's error.
			if isSwitchable(lastErr, lastErr.Status) {
				lastErr.AccountSwitch = true
			}
		}
		// 401 handling: a stored account gets one best-effort refresh; the
		// legacy token re-reads its sources (the desktop app may have
		// rotated the JWT underneath us). Either way the retry does not
		// consume the transient budget. Runs before the switch return so
		// a revoked-then-refreshed account recovers in place.
		if lastErr.Status == http.StatusUnauthorized && !refreshed {
			refreshed = true
			handled := false
			switch {
			case acct.ID != "":
				for _, a := range accounts.List() {
					if a.ID == acct.ID {
						if fresh, err := auth.RefreshPlanJWT(ctx, a.RefreshToken); err == nil {
							claims, _ := auth.DecodeJWT(fresh.JWT)
							var exp int64
							if claims != nil {
								if e, ok := claims["exp"].(float64); ok {
									exp = int64(e) * 1000
								}
							}
							accounts.Upsert(acct.ID, acct.Label, fresh.JWT, fresh.RefreshToken, fresh.AccessToken, exp)
							bearer = fresh.JWT
							handled = true
							n--
						}
						break
					}
				}
			case o.JWT == "":
				if fresh := auth.ResolvePlanJWT(""); fresh != "" && fresh != bearer {
					bearer = fresh
					handled = true
					n--
				}
			}
			if handled {
				continue
			}
		}
		if lastErr.AccountSwitch {
			return nil, lastErr
		}
		if !isTransient(lastErr) || n >= maxAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, &UpstreamError{Msg: "client went away", Status: 499, Kind: "upstream"}
		case <-time.After(time.Duration(baseMs*(1<<n)) * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = &UpstreamError{Msg: "upstream request failed", Status: 502, Kind: "upstream"}
	}
	return nil, lastErr
}

// attemptOnce performs one upstream POST.
func attemptOnce(ctx context.Context, client *http.Client, acct candidate, bearer string, o SendOpts, timeout time.Duration) (*http.Response, error) {
	deviceID := firstNonEmpty(acct.DeviceID, identity.ResolveDeviceMid(), newUUID())
	sessionID := systemprompt.SessionIDFor(o.ClientSessionID, acct.SessionSeed)
	requestID := newUUID()
	traceID := newUUID()
	queryID := "01a1" + requestID[4:]

	headers := identity.BuildLLMHeaders(systemprompt.Captured().AnthropicVersion, systemprompt.Captured().AnthropicBeta, identity.LLMHeaderOpts{
		SessionID: sessionID, RequestID: requestID, TraceID: traceID, QueryID: queryID,
	})
	headers["authorization"] = "Bearer " + bearer
	headers["content-type"] = "application/json"
	if streamTrue(o.Body) {
		headers["accept"] = "text/event-stream"
	} else {
		headers["accept"] = "application/json"
	}
	payload, err := ShapePlanBody(o.Body, sessionID, deviceID, acct.UserID)
	if err != nil {
		return nil, &UpstreamError{Msg: "shape body: " + err.Error(), Status: 500, Kind: "config"}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, &UpstreamError{Msg: "marshal body: " + err.Error(), Status: 500, Kind: "config"}
	}

	// The lane is a process-wide queue, so one hung upstream socket would
	// stall every later request behind it. Race a hard deadline against the
	// caller's context (AbortSignal.any equivalent).
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	// NO deferred cancel: the response body keeps streaming after this
	// function returns, and canceling here would kill it mid-flight. The
	// returned body is wrapped so cancel runs when the consumer closes it.
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, InferenceOrigin+PlanAnthropicPath, bytes.NewReader(raw))
	if err != nil {
		cancel()
		return nil, &UpstreamError{Msg: "build request: " + err.Error(), Status: 500, Kind: "config"}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		if callCtx.Err() != nil && ctx.Err() == nil {
			return nil, &UpstreamError{Msg: "upstream timeout", Status: 504, Kind: "upstream"}
		}
		return nil, &UpstreamError{Msg: "upstream fetch failed: " + err.Error(), Status: 502, Kind: "upstream"}
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelBody runs the request cancel when the consumer closes the body —
// the Go equivalent of letting the fetch signal live until the stream ends.
type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (b *cancelBody) Close() error {
	b.once.Do(b.cancel)
	return b.ReadCloser.Close()
}

func streamTrue(body map[string]any) bool {
	b, _ := body["stream"].(bool)
	return b
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// osGetenv exists so tests can stub the environment.
var osGetenv = os.Getenv
