import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import { AUTH_COOKIE, createAuth, isBrowserNavigation, parseCookies } from "../src/auth.js";

const PASSWORD = "hunter2";
const TOKEN = "a".repeat(64);

function makeReq(headers = {}) {
  return { headers };
}

function makeRes() {
  const res = {
    statusCode: null,
    headers: {},
    cookies: [],
    body: null,
    set(name, value) {
      res.headers[name.toLowerCase()] = value;
      return res;
    },
    append(name, value) {
      if (name.toLowerCase() === "set-cookie") res.cookies.push(value);
      return res;
    },
    status(code) {
      res.statusCode = code;
      return res;
    },
    type() {
      return res;
    },
    send(body) {
      res.body = body;
      return res;
    },
  };
  return res;
}

function basicHeader(password, user = "") {
  return `Basic ${Buffer.from(`${user}:${password}`, "utf8").toString("base64")}`;
}

const auth = createAuth({ password: PASSWORD, gatewayToken: TOKEN });

test("basic auth with the right password authorizes and issues a session", () => {
  const req = makeReq({ authorization: basicHeader(PASSWORD) });
  assert.equal(auth.authorize(req), "password");

  const res = makeRes();
  auth.issueSession(req, res);
  assert.equal(res.cookies.length, 1);
  const cookie = res.cookies[0];
  assert.match(cookie, new RegExp(`^${AUTH_COOKIE}=v1\\.\\d+\\.[0-9a-f]{64};`));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, /Path=\//);
});

test("a wrong password is rejected", () => {
  assert.equal(auth.authorize(makeReq({ authorization: basicHeader("nope") })), null);
  assert.equal(auth.authorize(makeReq()), null);
});

// Regression for the endless login dialog: the Control UI replaces the browser's
// cached Basic credentials with its own gateway Bearer token on API/SSE calls.
test("a session cookie survives an app-supplied Bearer Authorization header", () => {
  const res = makeRes();
  auth.issueSession(makeReq(), res);
  const cookie = res.cookies[0].split(";")[0];

  const apiReq = makeReq({ cookie, authorization: "Bearer some-control-ui-token" });
  assert.equal(auth.authorize(apiReq), "cookie");
});

test("a forged or expired session cookie is rejected", () => {
  const expired = `${AUTH_COOKIE}=${auth.signSession(Date.now() - 1000)}`;
  assert.equal(auth.authorize(makeReq({ cookie: expired })), null);

  const forged = `${AUTH_COOKIE}=v1.${Date.now() + 60_000}.${"0".repeat(64)}`;
  assert.equal(auth.authorize(makeReq({ cookie: forged })), null);

  // A session signed with a different password/token pair must not be accepted.
  const other = createAuth({ password: "other", gatewayToken: TOKEN });
  const foreign = `${AUTH_COOKIE}=${other.signSession(Date.now() + 60_000)}`;
  assert.equal(auth.authorize(makeReq({ cookie: foreign })), null);
});

test("non-browser clients may authenticate with the gateway token", () => {
  assert.equal(auth.authorize(makeReq({ authorization: `Bearer ${TOKEN}` })), "token");
  assert.equal(auth.authorize(makeReq({ authorization: "Bearer wrong" })), null);
});

test("everything is open when no password is configured", () => {
  const open = createAuth({ password: "", gatewayToken: TOKEN });
  assert.equal(open.authorize(makeReq()), "open");
});

// Regression for the popup storm: only top-level navigations may trigger the
// native browser login dialog, never XHR/fetch/SSE.
test("WWW-Authenticate is sent for navigations only", () => {
  const navRes = makeRes();
  auth.deny(makeReq({ "sec-fetch-dest": "document" }), navRes);
  assert.equal(navRes.statusCode, 401);
  assert.equal(navRes.headers["www-authenticate"], 'Basic realm="OpenClaw"');

  for (const headers of [
    { "sec-fetch-dest": "empty", "sec-fetch-mode": "cors" },
    { accept: "application/json" },
    { accept: "text/event-stream" },
  ]) {
    const res = makeRes();
    auth.deny(makeReq(headers), res);
    assert.equal(res.statusCode, 401);
    assert.equal(res.headers["www-authenticate"], undefined);
  }
});

test("isBrowserNavigation prefers Sec-Fetch-Dest over Accept", () => {
  assert.equal(
    isBrowserNavigation(makeReq({ "sec-fetch-dest": "empty", accept: "text/html" })),
    false,
  );
  assert.equal(isBrowserNavigation(makeReq({ accept: "text/html,*/*" })), true);
});

test("parseCookies handles multiple values and whitespace", () => {
  assert.deepEqual(parseCookies("a=1; b=two ; c=3"), { a: "1", b: "two", c: "3" });
  assert.deepEqual(parseCookies(undefined), {});
});

test("websocket upgrades are authorized before the gateway token is injected", () => {
  const src = fs.readFileSync(new URL("../src/server.js", import.meta.url), "utf8");
  const idx = src.indexOf('server.on("upgrade"');
  assert.ok(idx >= 0);
  const handler = src.slice(idx, idx + 900);
  const authIdx = handler.indexOf("authorizeRequest(req)");
  const injectIdx = handler.indexOf("attachGatewayAuthHeader(req)");
  assert.ok(authIdx >= 0, "upgrade handler must authorize the request");
  assert.ok(injectIdx > authIdx, "token injection must happen after authorization");
});

test("proxied requests do not forward wrapper Basic credentials to the gateway", () => {
  const src = fs.readFileSync(new URL("../src/server.js", import.meta.url), "utf8");
  const idx = src.indexOf("function attachGatewayAuthHeader");
  assert.ok(idx >= 0);
  const fn = src.slice(idx, idx + 600);
  assert.match(fn, /scheme === "basic"/);
});
