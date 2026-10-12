"use strict";

import assert from "assert";
import http from "http";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import httpAdapter from "../../../lib/adapters/http.js";
import buildURL from "../../../lib/helpers/buildURL.js";
import resolveConfig from "../../../lib/helpers/resolveConfig.js";
import axios from "../../../index.js";
import stream from "stream";
import { EventEmitter } from "events";
import vm from "vm";

const nodeMajorVersion = parseInt(process.versions.node.split(".")[0], 10);

function startServer(handler) {
  return new Promise(function (resolve, reject) {
    const server = http.createServer(handler);
    server.once("error", reject);
    server.listen(0, function () {
      resolve(server);
    });
  });
}

function stopServer(server) {
  return new Promise(function (resolve) {
    if (!server) {
      return resolve();
    }
    if (typeof server.closeAllConnections === "function") {
      server.closeAllConnections();
    }
    server.close(function () {
      resolve();
    });
  });
}

function serverURL(server) {
  return "http://127.0.0.1:" + server.address().port;
}

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.parseReviver;
    delete Object.prototype.headers;
    delete Object.prototype.customObj;
    delete Object.prototype.transitional;
    delete Object.prototype.responseType;
    delete Object.prototype.responseEncoding;
    delete Object.prototype.response;
    delete Object.prototype.url;
    delete Object.prototype.validateStatus;
    delete Object.prototype.data;
    delete Object.prototype.auth;
    delete Object.prototype.baseURL;
    delete Object.prototype.socketPath;
    delete Object.prototype.beforeRedirect;
    delete Object.prototype.insecureHTTPParser;
    delete Object.prototype.adapter;
    delete Object.prototype.httpAgent;
    delete Object.prototype.httpsAgent;
    delete Object.prototype.proxy;
    delete Object.prototype.maxContentLength;
    delete Object.prototype.maxBodyLength;
    delete Object.prototype.maxRedirects;
    delete Object.prototype.maxRate;
    delete Object.prototype.timeout;
    delete Object.prototype.timeoutErrorMessage;
    delete Object.prototype.cancelToken;
    delete Object.prototype.signal;
    delete Object.prototype.decompress;
    delete Object.prototype.params;
    delete Object.prototype.paramsSerializer;
    delete Object.prototype.method;
    delete Object.prototype.withCredentials;
    delete Object.prototype.fetchOptions;
    delete Object.prototype.username;
    delete Object.prototype.password;
    delete Object.prototype.hostname;
    delete Object.prototype.host;
    delete Object.prototype.port;
    delete Object.prototype.protocol;
    delete Object.prototype.get;
    delete Object.prototype.set;
    delete Object.prototype.customNested;
    delete Object.prototype.common;
    delete Object.prototype.encode;
    delete Object.prototype.serialize;
    delete Object.prototype.Authorization;
    delete Object.prototype.allowAbsoluteUrls;
    delete Object.prototype.createConnection;
    delete Object.prototype.cache;
    delete Object.prototype.redirect;
    delete Object.prototype.mode;
    delete Object.prototype.body;
    delete Object.prototype.visitor;
    delete Object.prototype.maxDepth;
    delete Object.prototype[Symbol.iterator];
    delete Object.prototype[Symbol.toStringTag];
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should not throw on own __proto__ key from JSON.parse payload", function () {
      const malicious = JSON.parse(
        '{"__proto__": {"polluted": "yes"}, "url": "/api/test"}',
      );
      let result;

      assert.doesNotThrow(function () {
        result = mergeConfig({}, malicious);
      });

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should ignore own constructor and prototype keys from JSON.parse payload", function () {
      const malicious = JSON.parse(
        '{"constructor": {"polluted": "yes"}, "prototype": {"polluted": "yes"}, "url": "/api/test"}',
      );
      const result = mergeConfig({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
    });

    // The tests above only assert that polluted keys never become *own*
    // properties of the merged config, which holds even without the value-read
    // guard because only own keys are iterated. The tests below exercise the
    // guard itself: when one config owns a key and the other does not, the
    // unguarded merge reads the missing side off the polluted prototype.

    it("should keep the default transformRequest when Object.prototype.transformRequest is polluted", function () {
      const safe = function safeTransformRequest(data) { return data; };
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({ transformRequest: [safe] }, { url: "/a" });
      assert.ok(Array.isArray(result.transformRequest), "transformRequest was replaced by the polluted value");
      assert.strictEqual(result.transformRequest.length, 1);
      assert.strictEqual(result.transformRequest[0], safe);
    });

    it("should keep the default transformResponse when Object.prototype.transformResponse is polluted", function () {
      const safe = function safeTransformResponse(data) { return data; };
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({ transformResponse: [safe] }, { url: "/a" });
      assert.ok(Array.isArray(result.transformResponse), "transformResponse was replaced by the polluted value");
      assert.strictEqual(result.transformResponse.length, 1);
      assert.strictEqual(result.transformResponse[0], safe);
    });

    it("should not fall back to a polluted transport for an own undefined transport", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a", transport: undefined });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false,
        "inherited Object.prototype.transport was copied into the merged config"
      );
    });

    it("should not take a url inherited from Object.prototype", function () {
      Object.prototype.url = "http://attacker.example/steal";
      const result = mergeConfig({ url: "/a" }, {});
      const ownUrl = Object.prototype.hasOwnProperty.call(result, "url") ? result.url : undefined;
      assert.notStrictEqual(ownUrl, "http://attacker.example/steal");
    });

    it("should not take a validateStatus inherited from Object.prototype", function () {
      const safe = function safeValidateStatus(status) { return status >= 200 && status < 300; };
      const evil = function evilValidateStatus() { return true; };
      Object.prototype.validateStatus = evil;
      const result = mergeConfig({ validateStatus: safe }, {});
      assert.notStrictEqual(result.validateStatus, evil);
    });

    it("should not fold prototype-inherited values into merged headers", function () {
      Object.prototype.headers = { polluted: "yes" };
      const result = mergeConfig({}, { headers: { a: "1" } });
      assert.strictEqual(result.headers.a, "1");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.headers, "polluted"),
        false,
        "inherited Object.prototype.headers leaked into the merged headers"
      );
    });

    it("should not fold prototype-inherited values into a merged custom key", function () {
      Object.prototype.customObj = { polluted: "yes" };
      const result = mergeConfig({}, { customObj: { safe: "value" } });
      assert.strictEqual(result.customObj.safe, "value");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.customObj, "polluted"),
        false,
        "inherited Object.prototype.customObj leaked into the merged value"
      );
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });
  });

  // GHSA-w9j2-pvgh-6h63: mergeDirectKeys must not inherit validateStatus from
  // Object.prototype (was using the `in` operator which traverses the chain).
  describe("GHSA-w9j2-pvgh-6h63 validateStatus merge", function () {
    let server;

    afterEach(async function () {
      await stopServer(server);
      server = null;
    });

    it("should not inherit a polluted validateStatus during mergeConfig", function () {
      Object.prototype.validateStatus = function () { return true; };

      const merged = mergeConfig(defaults, { url: "/x" });

      assert.strictEqual(merged.validateStatus, defaults.validateStatus);
    });

    it("should keep 4xx/5xx responses rejected when Object.prototype.validateStatus is polluted", async function () {
      this.timeout(10000);
      Object.prototype.validateStatus = function () { return true; };

      server = await startServer(function (req, res) {
        res.setHeader("Connection", "close");
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end('{"error":"unauthorized"}');
      });

      let threw = false;
      try {
        await axios.get(serverURL(server) + "/");
      } catch (err) {
        threw = true;
        assert.ok(err.response, "expected an HTTP error response");
        assert.strictEqual(err.response.status, 401);
      }
      assert.strictEqual(threw, true, "401 response was resolved instead of rejected");
    });
  });

  describe("axios request config", function () {
    it("should not crash when request config has own __proto__ key", function () {
      const malicious = JSON.parse(
        '{"__proto__": {"polluted": "yes"}, "baseURL": "http://example.com", "url": "/users"}',
      );
      let uri;

      assert.doesNotThrow(function () {
        uri = axios.getUri(malicious);
      });

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(uri, "http://example.com/users");
    });
  });

  describe("defaults.transformRequest", function () {
    const transformRequest = defaults.transformRequest[0];

    it("should not use a formSerializer inherited from Object.prototype", function () {
      let hijacked = false;
      Object.prototype.formSerializer = {
        visitor: function () {
          hijacked = true;
          return false;
        },
      };
      const headers = AxiosHeaders.from({
        "Content-Type": "application/x-www-form-urlencoded",
      });

      const result = transformRequest.call({}, { a: 1, b: "x" }, headers);

      assert.strictEqual(hijacked, false, "polluted formSerializer visitor was invoked");
      assert.strictEqual(result, "a=1&b=x");
    });

    it("should not use an env.FormData inherited from Object.prototype", function () {
      let hijacked = false;
      Object.prototype.env = {
        FormData: function EvilFormData() {
          hijacked = true;
          this.append = function () {};
        },
      };
      const headers = AxiosHeaders.from({ "Content-Type": "multipart/form-data" });

      transformRequest.call({}, { a: "1" }, headers);

      assert.strictEqual(hijacked, false, "polluted env.FormData was instantiated");
    });
  });

  describe("defaults.transformResponse", function () {
    const transformResponse = defaults.transformResponse[0];

    it("should not use transitional options inherited from Object.prototype", function () {
      Object.prototype.transitional = {
        silentJSONParsing: true,
        forcedJSONParsing: false,
        clarifyTimeoutError: false,
      };

      const result = transformResponse.call({}, '{"a":1}');

      assert.deepStrictEqual(result, { a: 1 });
    });

    it("should not use a responseType inherited from Object.prototype", function () {
      Object.prototype.responseType = "text";

      const result = transformResponse.call({}, '{"a":1}');

      assert.deepStrictEqual(result, { a: 1 });
    });

    it("should not attach a response inherited from Object.prototype to parse errors", function () {
      Object.prototype.response = { status: 1337, data: "forged" };
      const context = {
        responseType: "json",
        transitional: {
          silentJSONParsing: false,
          forcedJSONParsing: true,
          clarifyTimeoutError: false,
        },
      };
      let error;

      try {
        transformResponse.call(context, "{not json");
      } catch (e) {
        error = e;
      }

      assert.ok(error, "expected a parse error");
      assert.strictEqual(error.code, "ERR_BAD_RESPONSE");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(error, "response"),
        false,
        "polluted response was attached to the error"
      );
      assert.notStrictEqual(error.status, 1337);
    });
  });

  describe("http adapter", function () {
    let server;

    afterEach(async function () {
      await stopServer(server);
      server = null;
    });

    it("should not use a transport inherited from Object.prototype", async function () {
      let hijacked = false;
      Object.prototype.transport = {
        request: function () {
          hijacked = true;
          return http.request.apply(http, arguments);
        },
      };

      server = await startServer(function (req, res) {
        res.setHeader("Connection", "close");
        res.end("ok");
      });

      const res = await axios.get(serverURL(server) + "/", {
        auth: { username: "svc_account", password: "hunter2" },
      });

      assert.strictEqual(hijacked, false, "axios used a transport inherited from Object.prototype");
      assert.strictEqual(res.data, "ok");
    });

    it("should not use a responseType inherited from Object.prototype", async function () {
      Object.prototype.responseType = "arraybuffer";

      server = await startServer(function (req, res) {
        res.setHeader("Connection", "close");
        res.setHeader("Content-Type", "application/json");
        res.end('{"a":1}');
      });

      const res = await axios.get(serverURL(server) + "/");

      assert.deepStrictEqual(res.data, { a: 1 });
    });

    it("should not use a responseEncoding inherited from Object.prototype", async function () {
      Object.prototype.responseEncoding = "hex";

      server = await startServer(function (req, res) {
        res.setHeader("Connection", "close");
        res.setHeader("Content-Type", "application/json");
        res.end('{"a":1}');
      });

      const res = await axios.get(serverURL(server) + "/");

      assert.deepStrictEqual(res.data, { a: 1 });
    });

    it("should not use a transformResponse inherited from Object.prototype", async function () {
      let hijacked = false;
      // The gadget answers `true` when probed by assertOptions so it is not
      // rejected as an invalid option, and tampers with the data otherwise.
      Object.prototype.transformResponse = function (value, opt) {
        if (opt === "transformResponse") {
          return true;
        }
        hijacked = true;
        return { role: "admin" };
      };

      server = await startServer(function (req, res) {
        res.setHeader("Connection", "close");
        res.setHeader("Content-Type", "application/json");
        res.end('{"role":"user"}');
      });

      const res = await axios.get(serverURL(server) + "/");

      assert.strictEqual(hijacked, false, "polluted transformResponse was invoked");
      assert.deepStrictEqual(res.data, { role: "user" });
    });

    it("should not use a transformRequest inherited from Object.prototype", async function () {
      let hijacked = false;
      Object.prototype.transformRequest = function (value, opt) {
        if (opt === "transformRequest") {
          return true;
        }
        hijacked = true;
        return "hijacked";
      };

      server = await startServer(function (req, res) {
        let body = "";
        req.setEncoding("utf8");
        req.on("data", function (chunk) {
          body += chunk;
        });
        req.on("end", function () {
          res.setHeader("Connection", "close");
          res.end(body);
        });
      });

      const res = await axios.post(serverURL(server) + "/", { a: 1 }, {
        responseType: "text",
      });

      assert.strictEqual(hijacked, false, "polluted transformRequest was invoked");
      assert.strictEqual(res.data, '{"a":1}');
    });

    it("should not send a request body inherited from Object.prototype", async function () {
      Object.prototype.data = "hijacked";

      server = await startServer(function (req, res) {
        let body = "";
        req.setEncoding("utf8");
        req.on("data", function (chunk) {
          body += chunk;
        });
        req.on("end", function () {
          res.setHeader("Connection", "close");
          res.end("body:" + body);
        });
      });

      const res = await httpAdapter({
        url: serverURL(server) + "/",
        method: "post",
        headers: {},
      });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.data, "body:");
    });

    it("should not use an env.Blob inherited from Object.prototype for data: URIs", async function () {
      let hijacked = false;
      Object.prototype.env = {
        Blob: function EvilBlob() {
          hijacked = true;
        },
      };

      try {
        await httpAdapter({
          url: "data:text/plain;base64,SGVsbG8=",
          method: "get",
          responseType: "blob",
          headers: {},
        });
      } catch (e) {
        // Blob is not available on every supported Node.js version; only the
        // hijack matters here.
      }

      assert.strictEqual(hijacked, false, "polluted env.Blob was instantiated");
    });
  });

  // GHSA-q8qp-cvcw-x6jj: five config properties were read via direct property
  // access in the http adapter and resolveConfig, bypassing hasOwnProperty and
  // allowing prototype pollution gadgets (auth, baseURL, socketPath,
  // beforeRedirect, insecureHTTPParser).
  describe('GHSA-q8qp-cvcw-x6jj http adapter gadgets', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ headers: req.headers, url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function stopServer(server) {
      return new Promise((resolve) => server.close(resolve));
    }

    it('should not pick up Object.prototype.auth as an Authorization header', async function () {
      this.timeout(10000);
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.data.headers.authorization, undefined);
      } finally {
        await stopServer(server);
      }
    });

    it('should not pick up Object.prototype.socketPath and redirect the request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/api');
      } finally {
        await stopServer(server);
      }
    });

    it('should not invoke Object.prototype.beforeRedirect during redirects', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.prototype.beforeRedirect = function polluted() {
        hijackCalled = true;
      };

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(hijackCalled, false);
      } finally {
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should not enable insecureHTTPParser via Object.prototype', async function () {
      if (nodeMajorVersion < 14) this.skip();
      this.timeout(10000);
      // A raw TCP server emits a response that uses LF-only line terminators
      // instead of CRLF. Node's strict HTTP parser rejects this payload with
      // HPE_CR_EXPECTED; the insecure parser accepts it. Verified: with an
      // explicit `insecureHTTPParser: true` on the request config, this
      // payload is parsed successfully — so if Object.prototype.insecureHTTPParser
      // were picked up, the request would succeed. The request must fail when
      // the gadget is properly blocked.
      Object.prototype.insecureHTTPParser = true;

      const net = await import('net');
      const malformedPayload =
        'HTTP/1.1 200 OK\n' +
        'Content-Type: application/json\n' +
        'Content-Length: 2\n' +
        '\n' +
        '{}';
      const malformed = await new Promise((resolve) => {
        const srv = net.createServer((socket) => {
          socket.once('data', () => socket.end(malformedPayload));
        });
        srv.listen(0, '127.0.0.1', () => resolve(srv));
      });
      const { port } = malformed.address();

      try {
        let threw = false;
        let caughtCode = '';
        try {
          await axios.get(`http://127.0.0.1:${port}/`, {
            transitional: { clarifyTimeoutError: false },
          });
        } catch (err) {
          threw = true;
          caughtCode = String(err && (err.code || err.message));
        }
        assert.strictEqual(
          threw,
          true,
          `request should be rejected by the strict HTTP parser (got: ${caughtCode || 'success'})`
        );
        // The exact llhttp code for LF-only line terminators varies across
        // Node versions (historically HPE_LF_EXPECTED, more recently
        // HPE_CR_EXPECTED). Match any parser error to remain stable across
        // Node releases while still confirming the strict parser rejected
        // the payload.
        assert.match(
          caughtCode,
          /^HPE_/,
          `expected an HPE_* parser error, got: ${caughtCode}`
        );
      } finally {
        await new Promise((resolve) => malformed.close(resolve));
      }
    });

    it('should not pass insecureHTTPParser: true to http.request via Object.prototype', async function () {
      this.timeout(10000);
      Object.prototype.insecureHTTPParser = true;

      let capturedValue;
      const origRequest = http.request;
      http.request = function(options, callback) {
        capturedValue = options.insecureHTTPParser;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
      } catch (_) {}
      finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedValue, false);
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.auth', async function () {
      this.timeout(10000);
      // setProxy reads `proxy.auth` directly. When `proxy` is a
      // URL instance from the environment proxy or a plain object without an own `auth`,
      // a polluted Object.prototype.auth would otherwise be base64-encoded into the
      // Proxy-Authorization header, leaking attacker-controlled credentials.
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.auth must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.username', async function () {
      this.timeout(10000);
      // The setProxy username/password branch builds basic creds from `proxy.username`
      // and `proxy.password`. For a plain object proxy, both reads must be guarded
      // against prototype pollution.
      Object.prototype.username = 'attacker';
      Object.prototype.password = 'exfil';

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.username must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });

    it('should not route through a polluted Object.prototype.hostname when the proxy config uses host', async function () {
      this.timeout(10000);
      // setProxy resolves the proxy host as `proxy.hostname || proxy.host`. The
      // documented proxy config only sets `host`, so an unguarded read would let a
      // polluted Object.prototype.hostname redirect proxying to an attacker host.
      Object.prototype.hostname = 'attacker-proxy.invalid';

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      let capturedHostname;
      const origRequest = http.request;
      http.request = function (options) {
        capturedHostname = options.hostname;
        return origRequest.apply(this, arguments);
      };

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
          maxRedirects: 0,
        });
        assert.strictEqual(res.status, 200);
      } finally {
        http.request = origRequest;
        await stopServer(target);
        await stopServer(proxy);
      }

      assert.strictEqual(capturedHostname, '127.0.0.1');
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj resolveConfig baseURL gadget', function () {
    // The baseURL branch in buildFullPath only runs when the requested URL is
    // relative (or allowAbsoluteUrls === false). An absolute URL would skip
    // baseURL regardless of pollution and would not exercise the gadget. We
    // therefore issue a relative GET and assert that either:
    //   - the request fails (no host to resolve) because baseURL is correctly
    //     absent from the merged config, OR
    //   - the request is fulfilled without hitting the hijacker.
    // Critically, hijackHit must always be false.
    it('should not hijack relative-URL requests via Object.prototype.baseURL', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get('/api');
        } catch (_err) {
          threw = true;
        }
        // Either the request fails (desired — no baseURL means no host) or it
        // resolves, but it must NOT hit the polluted hijacker.
        assert.strictEqual(hijackHit, false);
        assert.strictEqual(threw, true);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
      }
    });

    // Second variant using allowAbsoluteUrls: false to force the baseURL path
    // even for a fully-qualified requested URL.
    it('should not hijack requests via Object.prototype.baseURL with allowAbsoluteUrls:false', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      const target = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
      const { port: targetPort } = target.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        // If the gadget were picked up, combineURLs(hijacker, `http://target`)
        // would route to the hijacker. It must not.
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${targetPort}/api`, {
            allowAbsoluteUrls: false,
          });
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        // allowAbsoluteUrls:false + no baseURL → combineURLs not invoked
        // (baseURL falsy) → returns requested URL as-is → target receives it.
        // If baseURL were inherited from prototype, it would be truthy and
        // combineURLs would be invoked, routing to the hijacker.
        assert.strictEqual(threw, false);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
        await new Promise((resolve) => target.close(resolve));
      }
    });
  });

  // Structural defense: mergeConfig returns a null-prototype object, so any
  // property read that is not an own property of config cannot inherit from
  // Object.prototype. Adding a new key to Object.prototype must never appear
  // as a property of the merged config.
  describe('mergeConfig null-prototype structural defense', function () {
    it('should return an object whose prototype is null', function () {
      const merged = mergeConfig({ url: '/x' }, { method: 'get' });
      assert.strictEqual(Object.getPrototypeOf(merged), null);
    });

    it('should preserve hasOwnProperty as a callable own slot', function () {
      const merged = mergeConfig({}, { url: '/x', method: 'get' });
      assert.strictEqual(typeof merged.hasOwnProperty, 'function');
      assert.strictEqual(merged.hasOwnProperty('url'), true);
      assert.strictEqual(merged.hasOwnProperty('method'), true);
      assert.strictEqual(merged.hasOwnProperty('bogus'), false);
    });

    it('should not serialize hasOwnProperty slot via Object.keys', function () {
      const merged = mergeConfig({ url: '/x' }, {});
      assert.ok(!Object.keys(merged).includes('hasOwnProperty'));
    });

    it('should not expose arbitrary polluted keys as inherited properties', function () {
      Object.prototype.polluted = 'attacker';
      try {
        const merged = mergeConfig({ url: '/x' }, {});
        assert.strictEqual(merged.polluted, undefined);
      } finally {
        delete Object.prototype.polluted;
      }
    });
  });

  // Verify every gadget enumerated in the audit (extension of GHSA-q8qp-cvcw-x6jj)
  // is neutralized end-to-end by the null-prototype config.
  describe('Full gadget coverage via null-prototype config', function () {
    function startEcho(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          let body = '';
          req.on('data', (c) => (body += c));
          req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              url: req.url,
              method: req.method,
              headers: req.headers,
              body,
            }));
          });
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    it('should ignore polluted transformRequest', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformRequest = function polluted(data) {
        invoked = true;
        return 'INJECTED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.post(`http://127.0.0.1:${port}/`, { hello: 'world' });
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data.body, 'INJECTED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transformResponse', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformResponse = function polluted() {
        invoked = true;
        return 'HIJACKED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data, 'HIJACKED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted adapter', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.adapter = function pollutedAdapter() {
        hijacked = true;
        return Promise.resolve({ data: 'pwned', status: 200, statusText: 'OK', headers: {}, config: {}, request: {} });
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(hijacked, false);
        assert.notStrictEqual(res.data, 'pwned');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted httpAgent', async function () {
      this.timeout(10000);
      let agentUsed = false;
      Object.prototype.httpAgent = new http.Agent({
        keepAlive: false,
      });
      // Wrap createConnection to detect usage
      const origCreate = Object.prototype.httpAgent.createConnection;
      Object.prototype.httpAgent.createConnection = function (...args) {
        agentUsed = true;
        return origCreate.apply(this, args);
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(agentUsed, false);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted proxy', async function () {
      this.timeout(10000);
      Object.prototype.proxy = {
        protocol: 'http',
        host: '127.0.0.1',
        port: 1, // would fail if actually used
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxContentLength', async function () {
      this.timeout(10000);
      // Polluted tiny limit would reject a normal response if applied.
      Object.prototype.maxContentLength = 1;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxRedirects', async function () {
      this.timeout(10000);
      // Pollute with 0 — if picked up, follow-redirects path would be skipped.
      // We make sure regular requests still succeed via the expected path.
      Object.prototype.maxRedirects = 0;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted timeout at the merged config level', function () {
      Object.prototype.timeout = 1;
      const merged = mergeConfig({}, { url: '/x' });
      assert.strictEqual(Object.prototype.hasOwnProperty.call(merged, 'timeout'), false);
      assert.strictEqual(merged.timeout, undefined);
    });

    it('should ignore polluted timeoutErrorMessage', async function () {
      this.timeout(10000);
      Object.prototype.timeoutErrorMessage = 'INJECTED_TIMEOUT';
      // Not easy to assert without triggering a real timeout; just confirm
      // normal requests still succeed and do not read the polluted key.
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transitional', async function () {
      this.timeout(10000);
      Object.prototype.transitional = { forcedJSONParsing: true, silentJSONParsing: false };
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted params and paramsSerializer', async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      Object.prototype.params = { injected: 'yes' };
      Object.prototype.paramsSerializer = function polluted() {
        serializerInvoked = true;
        return 'injected=yes';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/x`);
        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(res.data.url, '/x');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted method', async function () {
      this.timeout(10000);
      Object.prototype.method = 'DELETE';
      const server = await startEcho();
      const { port } = server.address();
      try {
        // axios.get should still send GET, not DELETE.
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(res.data.method, 'GET');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted decompress', async function () {
      this.timeout(10000);
      Object.prototype.decompress = false;
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted responseType', async function () {
      this.timeout(10000);
      Object.prototype.responseType = 'arraybuffer';
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        // When responseType is not set on config, json parsing should apply
        // and res.data should be an object, not an ArrayBuffer/Buffer.
        assert.strictEqual(typeof res.data, 'object');
        assert.ok(!Buffer.isBuffer(res.data));
      } finally {
        await stop(server);
      }
    });
  });

  // utils.merge previously read `result[targetKey]` directly, which walks the
  // prototype chain. A polluted Object.prototype.<key> object would surface as
  // the existing value and be merged into the result.
  describe('utils.merge prototype-chain read', function () {
    it('should not pick up polluted Object.prototype.<key> as the existing value', function () {
      Object.prototype.headers = { evil: 'yes' };

      const result = utils.merge({}, { headers: { 'Content-Type': 'application/json' } });

      assert.strictEqual(result.headers.evil, undefined);
      assert.strictEqual(result.headers['Content-Type'], 'application/json');
    });

    it('should not absorb polluted nested objects when the key is absent from inputs', function () {
      // When the source does not carry `customNested`, the merged result should
      // not surface it either, even if Object.prototype carries it.
      Object.prototype.customNested = { evil: 'yes' };

      const result = utils.merge({}, { safe: 'value' });

      assert.strictEqual(result.hasOwnProperty('customNested'), false);
      assert.strictEqual(result.safe, 'value');
    });

    it('should not send headers from a polluted Object.prototype.common bucket on the wire', async function () {
      this.timeout(10000);
      // mergeConfig merges the default headers via utils.merge({}, defaults.headers).
      // Reading `result.common` through the prototype chain would pick up the
      // polluted bucket and copy its keys into every outgoing request.
      Object.prototype.common = { 'X-Injected': 'pwned' };

      const server = await startServer(function (req, res) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ headers: req.headers }));
      });

      try {
        const res = await axios.get(serverURL(server) + '/api');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['x-injected'],
          undefined,
          'polluted Object.prototype.common must not inject request headers'
        );
      } finally {
        await stopServer(server);
      }
    });
  });

  // Object.defineProperty calls a HasProperty check on `get`/`set` of the
  // descriptor. A polluted Object.prototype.get with a non-function value would
  // throw TypeError at every defineProperty site that uses a plain literal
  // descriptor. Each fixed site should be shielded with `__proto__: null`.
  describe('Object.defineProperty descriptor literals', function () {
    it('should construct AxiosHeaders accessor methods when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      // AxiosHeaders.accessor uses Object.defineProperty on the prototype.
      // Triggering a fresh accessor definition exercises the descriptor literal.
      AxiosHeaders.accessor('X-Pp-Test');

      const h = new AxiosHeaders();
      h.setXPpTest('value');
      assert.strictEqual(h.getXPpTest(), 'value');
    });

    it('should not throw in mergeConfig when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const result = mergeConfig({}, { url: '/x', method: 'get' });

      assert.strictEqual(result.url, '/x');
      assert.strictEqual(result.method, 'get');
      assert.strictEqual(typeof result.hasOwnProperty, 'function');
    });

    it('should not throw in utils.inherits when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      function Parent() {}
      function Child() {}
      utils.inherits(Child, Parent);

      assert.strictEqual(Child.prototype.constructor, Child);
      assert.strictEqual(Child.super, Parent.prototype);
    });

    it('should not throw in utils.extend when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      // utils.extend backs axios.create(); both the bound-function and the
      // plain-value descriptor literals must be shielded.
      const target = {};
      utils.extend(target, {
        fn: function () { return this.tag; },
        plain: 1
      }, { tag: 'ctx' });

      assert.strictEqual(target.fn(), 'ctx');
      assert.strictEqual(target.plain, 1);
    });

    it('should also be shielded against a polluted Object.prototype.set', function () {
      Object.prototype.set = 'attacker';

      // Same surface as `get` — ToPropertyDescriptor checks both. One spot-check
      // covers them all since they share the same fix.
      const result = mergeConfig({}, { url: '/y' });
      assert.strictEqual(result.url, '/y');
    });
  });

  // End-to-end regressions covering published advisory PoCs against full axios
  // request flow. Each test mirrors the exploit scenario from the advisory and
  // asserts the attack does not succeed.
  describe('advisory regression — full request flow', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler);
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    // Full MITM via prototype pollution gadget in
    // `config.proxy`. mergeConfig must not surface a polluted Object.prototype.proxy
    // as the merged config's proxy, otherwise every request would route through
    // an attacker-controlled host.
    it('polluted Object.prototype.proxy must not redirect requests through an attacker proxy', async function () {
      this.timeout(10000);
      const proxyHits = [];
      const attackerProxy = await startServer((req, res) => {
        proxyHits.push({
          url: req.url,
          authorization: req.headers.authorization,
          host: req.headers.host,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });

      const realHits = [];
      const realServer = await startServer((req, res) => {
        realHits.push({ url: req.url });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"data":"real"}');
      });

      try {
        Object.prototype.proxy = {
          protocol: 'http',
          host: '127.0.0.1',
          port: attackerProxy.address().port,
        };

        const realPort = realServer.address().port;
        const res = await axios.get(`http://127.0.0.1:${realPort}/api/secrets`, {
          auth: { username: 'admin', password: 'SuperSecret123!' },
        });

        assert.strictEqual(proxyHits.length, 0, 'attacker proxy must not receive any request');
        assert.strictEqual(realHits.length, 1, 'request must reach the real target');
        assert.deepStrictEqual(res.data, { data: 'real' });
      } finally {
        await stop(attackerProxy);
        await stop(realServer);
      }
    });

    // Credential theft and response hijacking via
    // prototype pollution gadget in config merge. A polluted
    // Object.prototype.transformResponse function would otherwise execute with
    // `this = config`, exposing `auth.username`/`auth.password` to the attacker.
    it('polluted Object.prototype.transformResponse must not be invoked or leak request credentials', async function () {
      this.timeout(10000);
      let invoked = false;
      let stolen = null;
      Object.prototype.transformResponse = function pollutedTransform(data) {
        invoked = true;
        stolen = {
          url: this && this.url,
          username: this && this.auth && this.auth.username,
          password: this && this.auth && this.auth.password,
          data,
        };
        return true;
      };

      const server = await startServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"secret":"keep-me"}');
      });

      try {
        const { port } = server.address();
        const res = await axios.get(`http://127.0.0.1:${port}/users`, {
          auth: { username: 'svc-account', password: 'prod-secret-key-123!' },
        });

        assert.strictEqual(invoked, false, 'polluted transformResponse must not run');
        assert.strictEqual(stolen, null, 'no request context must be captured');
        assert.deepStrictEqual(
          res.data,
          { secret: 'keep-me' },
          'response data must reach the caller untampered'
        );
      } finally {
        await stop(server);
      }
    });
  });

  // GHSA-jqh4-m9w3-8hp9: nested option objects (auth, paramsSerializer), the
  // bodyless-method `data` shortcut and Symbol-keyed members (Symbol.iterator,
  // Symbol.toStringTag) were read from ordinary objects that still inherit from
  // Object.prototype, so a polluted Object.prototype could inject credentials,
  // serializers, request bodies or headers. Every such read must ignore values
  // that are reachable only through Object.prototype.
  describe('GHSA-jqh4-m9w3-8hp9 nested option and Symbol gadgets', function () {
    // Writable so positive paths that assign the same key (e.g. Node's URL
    // parser or a mocked XHR) are not broken by a read-only prototype slot.
    function definePolluted(key, value) {
      Object.defineProperty(Object.prototype, key, {
        value,
        configurable: true,
        writable: true,
      });
    }

    function createStubTransport(onRequest, responseHeaders) {
      return {
        request(options, handleResponse) {
          onRequest(options);
          const req = new EventEmitter();
          req.write = () => true;
          req.setTimeout = () => {};
          req.destroy = () => {};
          req.end = () => {
            const res = new stream.Readable({ read() {} });
            res.statusCode = 200;
            res.statusMessage = 'OK';
            res.headers = responseHeaders;
            res.rawHeaders = [];
            res.req = req;
            process.nextTick(() => {
              handleResponse(res);
              res.push(null);
            });
          };
          return req;
        },
      };
    }

    describe('utils.hasOwnInPrototypeChain / getSafeProp / isSafeIterable', function () {
      it('should ignore inherited symbol properties when validating plain Object', function () {
        try {
          Object.prototype[Symbol.iterator] = function* () {
            yield ['x-injected', 'yes'];
          };
          Object.prototype[Symbol.toStringTag] = 'Custom';

          assert.strictEqual(utils.isPlainObject({}), true);
          assert.strictEqual(utils.isPlainObject([]), false);
          assert.strictEqual(
            utils.isPlainObject({
              [Symbol.iterator]: function* () {
                yield ['x-own', 'yes'];
              },
            }),
            false
          );
          assert.strictEqual(utils.isPlainObject({ [Symbol.toStringTag]: 'Custom' }), false);
        } finally {
          delete Object.prototype[Symbol.iterator];
          delete Object.prototype[Symbol.toStringTag];
        }
      });

      it('should keep merging plain objects when only Symbol.toStringTag is polluted', function () {
        try {
          Object.prototype[Symbol.toStringTag] = 'Custom';

          assert.strictEqual(utils.isPlainObject({ a: 1 }), true);
          assert.strictEqual(utils.isPlainObject(Object.create(null)), true);

          const merged = utils.merge({}, { headers: { a: '1' } }, { headers: { b: '2' } });
          assert.deepStrictEqual(Object.keys(merged.headers).sort(), ['a', 'b']);
        } finally {
          delete Object.prototype[Symbol.toStringTag];
        }
      });

      it('should ignore an iterator inherited from a terminal null-prototype boundary', function () {
        // A terminal application template is indistinguishable from a mutated
        // foreign Object.prototype, so its inherited members fail closed.
        const proto = Object.create(null);
        proto[Symbol.iterator] = function* () {
          yield ['x', '1'];
        };

        const value = Object.create(proto);

        assert.strictEqual(utils.isPlainObject(value), true);
        assert.strictEqual(utils.isSafeIterable(value), false);
      });

      it('should still treat an iterator inherited from a non-terminal template as non-plain', function () {
        const proto = {
          *[Symbol.iterator]() {
            yield ['x', '1'];
          },
        };

        assert.strictEqual(utils.isPlainObject(Object.create(proto)), false);
        assert.strictEqual(utils.isSafeIterable(Object.create(proto)), true);
      });

      it('should not read polluted Object.prototype iterator accessors for safe iterable checks', function () {
        let accessed = false;

        try {
          Object.defineProperty(Object.prototype, Symbol.iterator, {
            configurable: true,
            get() {
              accessed = true;
              throw new Error('polluted iterator accessor');
            },
          });

          assert.strictEqual(utils.isSafeIterable({}), false);
          assert.strictEqual(utils.isSafeIterable(new Map()), true);
          assert.strictEqual(utils.isSafeIterable([]), true);
          assert.strictEqual(accessed, false);
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });

      it('should stop safe prototype-chain reads on cyclic Proxy prototypes', function () {
        let calls = 0;
        const proxy = new Proxy({}, {
          getPrototypeOf() {
            calls += 1;
            if (calls > 5) {
              throw new Error('cycled');
            }
            return proxy;
          },
        });

        assert.strictEqual(utils.hasOwnInPrototypeChain(proxy, 'missing'), false);
        assert.strictEqual(utils.getSafeProp(proxy, 'missing'), undefined);
        assert.ok(calls <= 2, 'prototype walk must stop on the first cycle, got ' + calls);
      });

      it('should honor own and template-inherited members but ignore Object.prototype in getSafeProp', function () {
        Object.prototype.polluted = 'attacker';

        class Options {
          serialize() {
            return 'class';
          }
        }

        const obj = Object.create({ inherited: 'template' });
        obj.own = 'own';

        assert.strictEqual(utils.getSafeProp(obj, 'own'), 'own');
        assert.strictEqual(utils.getSafeProp(obj, 'inherited'), 'template');
        assert.strictEqual(utils.getSafeProp(new Options(), 'serialize')(), 'class');
        assert.strictEqual(utils.getSafeProp(obj, 'polluted'), undefined);
        assert.strictEqual(utils.getSafeProp({}, 'polluted'), undefined);
        assert.strictEqual(utils.getSafeProp(null, 'polluted'), undefined);
        assert.strictEqual(utils.getSafeProp(undefined, 'polluted'), undefined);
      });
    });

    describe('AxiosHeaders iterable sources', function () {
      it('should not merge Object.prototype values into iterable headers', function () {
        try {
          Object.prototype.Authorization = 'polluted';

          const headers = new AxiosHeaders(new Map([['Authorization', 'real']]));

          assert.strictEqual(headers.get('authorization'), 'real');
        } finally {
          delete Object.prototype.Authorization;
        }
      });

      it('should not merge built-in Object.prototype members into iterable header entries', function () {
        const headers = new AxiosHeaders([['constructor', 'x']]);

        assert.strictEqual(headers.get('constructor'), 'x');
      });

      it('should still merge duplicate keys from an iterable source', function () {
        const headers = new AxiosHeaders([['x-dup', 'a'], ['x-dup', 'b']]);

        assert.deepStrictEqual(headers.get('x-dup'), ['a', 'b']);
      });

      it('should support objects with an own iterator as a key-value source object', function () {
        const headers = new AxiosHeaders();

        headers.set({
          *[Symbol.iterator]() {
            yield ['x', '123'];
          },
        });

        assert.strictEqual(headers.get('x'), '123');
      });

      it('should not use inherited Symbol.iterator as a key-value source object', function () {
        try {
          Object.prototype[Symbol.iterator] = function* () {
            yield ['x-app', 'changed'];
            yield ['x-injected', 'yes'];
          };

          const headers = new AxiosHeaders({
            'x-app': 'safe',
          });

          assert.strictEqual(headers.get('x-app'), 'safe');
          assert.strictEqual(headers.get('x-injected'), undefined);
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });

      it('should not read polluted Object.prototype Symbol.iterator accessors', function () {
        let accessed = false;

        try {
          Object.defineProperty(Object.prototype, Symbol.iterator, {
            configurable: true,
            get() {
              accessed = true;
              throw new Error('polluted iterator accessor');
            },
          });

          const headers = new AxiosHeaders({
            'x-app': 'safe',
          });

          assert.strictEqual(headers.get('x-app'), 'safe');
          assert.strictEqual(accessed, false);
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });

      it('should not consume an inherited Symbol.iterator for non-plain header sources', function () {
        try {
          Object.prototype[Symbol.iterator] = function* () {
            yield ['x-injected', 'yes'];
            yield ['authorization', 'Bearer CHANGED'];
          };

          // A class instance and an Object.create(...) object both have a direct
          // prototype other than Object.prototype, yet their only iterator comes
          // from the polluted Object.prototype — they must not be iterated.
          class HeaderBag {
            constructor() {
              this['authorization'] = 'Bearer VALID';
            }
          }

          const fromClass = new AxiosHeaders(new HeaderBag());
          assert.strictEqual(fromClass.get('x-injected'), undefined);
          assert.notStrictEqual(fromClass.get('authorization'), 'Bearer CHANGED');

          const created = Object.create({ 'x-app': 'safe' });
          created['authorization'] = 'Bearer VALID';
          const fromCreate = new AxiosHeaders(created);
          assert.strictEqual(fromCreate.get('x-injected'), undefined);
          assert.notStrictEqual(fromCreate.get('authorization'), 'Bearer CHANGED');
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });
    });

    describe('buildURL serializer options', function () {
      it('should ignore inherited serializer options', function () {
        let serializeInvoked = false;
        let encodeInvoked = false;

        definePolluted('serialize', function () {
          serializeInvoked = true;
          return 'inherited=1';
        });
        definePolluted('encode', function () {
          encodeInvoked = true;
          return 'inherited';
        });

        try {
          assert.strictEqual(buildURL('/foo', { value: 'a b' }, {}), '/foo?value=a+b');
          assert.strictEqual(serializeInvoked, false);
          assert.strictEqual(encodeInvoked, false);
        } finally {
          delete Object.prototype.serialize;
          delete Object.prototype.encode;
        }
      });

      it('should still honor serializer options inherited from a class or template', function () {
        class Serializer {
          serialize(params) {
            return 'custom=' + params.value;
          }
        }

        assert.strictEqual(buildURL('/foo', { value: 1 }, new Serializer()), '/foo?custom=1');

        const encoderOptions = Object.create({
          encode(value) {
            return String(value).toUpperCase();
          },
        });

        assert.strictEqual(buildURL('/foo', { value: 'ab' }, encoderOptions), '/foo?VALUE=AB');
        assert.strictEqual(
          buildURL('/foo', { value: 'ab' }, function (params) {
            return 'fn=' + params.value;
          }),
          '/foo?fn=ab'
        );
      });
    });

    describe('resolveConfig', function () {
      it('should ignore inherited nested auth fields', function () {
        if (typeof btoa === 'undefined') {
          this.skip();
          return;
        }

        definePolluted('username', 'inherited-user');
        definePolluted('password', 'inherited-pass');

        try {
          const config = resolveConfig({
            url: '/foo',
            auth: {},
          });

          assert.strictEqual(config.headers.get('Authorization'), 'Basic Og==');
        } finally {
          delete Object.prototype.username;
          delete Object.prototype.password;
        }
      });

      it('should keep own nested auth fields', function () {
        if (typeof btoa === 'undefined') {
          this.skip();
          return;
        }

        definePolluted('password', 'inherited-pass');

        try {
          const config = resolveConfig({
            url: '/foo',
            auth: { username: 'Aladdin' },
          });

          assert.strictEqual(config.headers.get('Authorization'), 'Basic QWxhZGRpbjo=');
        } finally {
          delete Object.prototype.password;
        }
      });

      it('should ignore inherited nested serializer fields', function () {
        let serializeInvoked = false;
        let encodeInvoked = false;

        definePolluted('serialize', function () {
          serializeInvoked = true;
          return 'inherited=1';
        });
        definePolluted('encode', function () {
          encodeInvoked = true;
          return 'inherited';
        });

        try {
          const config = resolveConfig({
            url: '/foo',
            params: { value: 'a b' },
            paramsSerializer: {},
          });

          assert.strictEqual(config.url, '/foo?value=a+b');
          assert.strictEqual(serializeInvoked, false);
          assert.strictEqual(encodeInvoked, false);
        } finally {
          delete Object.prototype.serialize;
          delete Object.prototype.encode;
        }
      });

      it('should ignore inherited params and paramsSerializer on a plain config', function () {
        let serializerInvoked = false;

        Object.prototype.params = { injected: '1' };

        assert.strictEqual(resolveConfig({ url: '/foo' }).url, '/foo');

        delete Object.prototype.params;

        definePolluted('paramsSerializer', function () {
          serializerInvoked = true;
          return 'inherited=1';
        });

        try {
          assert.strictEqual(
            resolveConfig({ url: '/foo', params: { value: 'a b' } }).url,
            '/foo?value=a+b'
          );
          assert.strictEqual(serializerInvoked, false);
        } finally {
          delete Object.prototype.paramsSerializer;
        }
      });
    });

    describe('Axios request helpers', function () {
      it('should ignore inherited data for bodyless method helpers', async function () {
        definePolluted('data', 'inherited-body');

        try {
          for (const method of ['delete', 'get', 'head', 'options']) {
            let seenData = 'unset';

            await axios[method]('/test', {
              adapter(config) {
                seenData = config.data;

                return Promise.resolve({
                  data: null,
                  status: 200,
                  statusText: 'OK',
                  headers: {},
                  config,
                  request: {},
                });
              },
            });

            assert.strictEqual(seenData, undefined, method + ' must not send an inherited body');
          }
        } finally {
          delete Object.prototype.data;
        }
      });

      it('should still send own data for bodyless method helpers', async function () {
        let seenData = 'unset';

        await axios.delete('/test', {
          data: 'own-body',
          adapter(config) {
            seenData = config.data;

            return Promise.resolve({
              data: null,
              status: 200,
              statusText: 'OK',
              headers: {},
              config,
              request: {},
            });
          },
        });

        assert.strictEqual(seenData, 'own-body');
      });

      it('should ignore inherited nested serializer fields in getUri', function () {
        let serializeInvoked = false;

        definePolluted('serialize', function () {
          serializeInvoked = true;
          return 'inherited=1';
        });

        try {
          assert.strictEqual(
            axios.getUri({
              url: '/foo',
              params: { value: 'a b' },
              paramsSerializer: {},
            }),
            '/foo?value=a+b'
          );
          assert.strictEqual(serializeInvoked, false);
        } finally {
          delete Object.prototype.serialize;
        }
      });
    });

    describe('http adapter', function () {
      it('should ignore inherited nested request option fields in http adapter', async function () {
        this.timeout(10000);

        const server = await startServer(function (req, res) {
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              authorization: req.headers.authorization,
              url: req.url,
            })
          );
        });

        definePolluted('username', 'inherited-user');
        definePolluted('password', 'inherited-pass');
        definePolluted('serialize', function () {
          return 'inherited=1';
        });

        try {
          const response = await axios.get(serverURL(server) + '/demo', {
            auth: {},
            params: { value: 'a b' },
            paramsSerializer: {},
            proxy: false,
          });

          assert.deepStrictEqual(response.data, {
            authorization: 'Basic Og==',
            url: '/demo?value=a+b',
          });
        } finally {
          delete Object.prototype.username;
          delete Object.prototype.password;
          delete Object.prototype.serialize;
          await stopServer(server);
        }
      });

      it('should ignore inherited proxy when http adapter receives a plain config', async function () {
        this.timeout(10000);

        const proxyEnvKeys = ['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY'];
        const originalProxyEnv = Object.create(null);
        let proxy;
        let target;
        let proxyHits = 0;
        let targetHits = 0;

        for (const key of proxyEnvKeys) {
          originalProxyEnv[key] = process.env[key];
          delete process.env[key];
        }

        try {
          proxy = await startServer(function (req, res) {
            proxyHits += 1;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ via: 'proxy', url: req.url }));
          });

          target = await startServer(function (req, res) {
            targetHits += 1;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ via: 'target', url: req.url }));
          });

          definePolluted('proxy', {
            protocol: 'http',
            host: '127.0.0.1',
            port: proxy.address().port,
          });

          const response = await httpAdapter({
            method: 'get',
            url: serverURL(target) + '/direct',
            headers: {},
            maxRedirects: 0,
            maxContentLength: -1,
            maxBodyLength: -1,
            timeout: 0,
          });
          const data = JSON.parse(response.data);

          assert.strictEqual(proxyHits, 0);
          assert.strictEqual(targetHits, 1);
          assert.deepStrictEqual(data, { via: 'target', url: '/direct' });
        } finally {
          delete Object.prototype.proxy;

          for (const key of proxyEnvKeys) {
            if (originalProxyEnv[key] === undefined) {
              delete process.env[key];
            } else {
              process.env[key] = originalProxyEnv[key];
            }
          }

          await stopServer(target);
          await stopServer(proxy);
        }
      });

      it('should ignore inherited paramsSerializer when http adapter receives a plain config', async function () {
        this.timeout(10000);

        let server;
        let serializerInvoked = false;

        definePolluted('paramsSerializer', function () {
          serializerInvoked = true;
          return 'inherited=1';
        });

        try {
          server = await startServer(function (req, res) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ url: req.url }));
          });

          const response = await httpAdapter({
            method: 'get',
            url: serverURL(server) + '/direct',
            headers: {},
            params: { value: 'a b' },
            proxy: false,
            maxRedirects: 0,
            maxContentLength: -1,
            maxBodyLength: -1,
            timeout: 0,
          });
          const data = JSON.parse(response.data);

          assert.strictEqual(serializerInvoked, false);
          assert.deepStrictEqual(data, { url: '/direct?value=a+b' });
        } finally {
          delete Object.prototype.paramsSerializer;
          await stopServer(server);
        }
      });

      it('should ignore inherited baseURL/allowAbsoluteUrls when http adapter receives a plain config', async function () {
        this.timeout(10000);

        let hijackHits = 0;
        let targetHits = 0;

        const hijacker = await startServer(function (req, res) {
          hijackHits += 1;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ via: 'hijacker' }));
        });
        const target = await startServer(function (req, res) {
          targetHits += 1;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ via: 'target', url: req.url }));
        });

        Object.prototype.baseURL = serverURL(hijacker);
        Object.prototype.allowAbsoluteUrls = false;

        try {
          const response = await httpAdapter({
            method: 'get',
            url: serverURL(target) + '/direct',
            headers: {},
            proxy: false,
            maxRedirects: 0,
          });

          assert.strictEqual(hijackHits, 0, 'polluted baseURL must not reroute the request');
          assert.strictEqual(targetHits, 1);
          assert.deepStrictEqual(JSON.parse(response.data), { via: 'target', url: '/direct' });
        } finally {
          delete Object.prototype.baseURL;
          delete Object.prototype.allowAbsoluteUrls;
          await stopServer(hijacker);
          await stopServer(target);
        }
      });

      it('should ignore inherited size limits when http adapter receives a plain config', async function () {
        this.timeout(10000);

        const server = await startServer(function (req, res) {
          let body = '';
          req.on('data', function (chunk) {
            body += chunk;
          });
          req.on('end', function () {
            res.end(body);
          });
        });

        Object.prototype.maxBodyLength = 1;
        Object.prototype.maxContentLength = 1;

        try {
          const response = await httpAdapter({
            method: 'post',
            url: serverURL(server) + '/echo',
            headers: {},
            data: 'hello world',
            proxy: false,
            maxRedirects: 0,
          });

          assert.strictEqual(response.data, 'hello world');
        } finally {
          delete Object.prototype.maxBodyLength;
          delete Object.prototype.maxContentLength;
          await stopServer(server);
        }
      });

      it('should not use inherited Symbol.iterator for request or response headers', async function () {
        let capturedHeaders;
        const stubTransport = createStubTransport(function (options) {
          capturedHeaders = { ...options.headers };
        }, { 'x-server': 'real' });

        try {
          Object.prototype[Symbol.iterator] = function* () {
            yield ['X-Injected', 'yes'];
            yield ['Authorization', 'Bearer CHANGED'];
          };

          const response = await axios.get('http://stub.invalid/', {
            headers: {
              Authorization: 'Bearer VALID_USER_TOKEN',
              'X-App': 'safe',
            },
            transport: stubTransport,
            maxRedirects: 0,
            proxy: false,
          });

          assert.ok(capturedHeaders, 'transport was not invoked');
          assert.strictEqual(capturedHeaders['X-App'], 'safe');
          assert.strictEqual(
            capturedHeaders.Authorization || capturedHeaders.authorization,
            'Bearer VALID_USER_TOKEN'
          );
          assert.strictEqual(capturedHeaders['X-Injected'] || capturedHeaders['x-injected'], undefined);
          assert.strictEqual(response.headers.get('x-server'), 'real');
          assert.strictEqual(response.headers.get('x-injected'), undefined);
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });

      it('should not drop request or response headers under a polluted Symbol.toStringTag', async function () {
        let capturedHeaders;
        const stubTransport = createStubTransport(function (options) {
          capturedHeaders = { ...options.headers };
        }, { 'x-server': 'real' });

        try {
          Object.prototype[Symbol.toStringTag] = 'Custom';

          const response = await axios.get('http://stub.invalid/', {
            headers: {
              Authorization: 'Bearer VALID_USER_TOKEN',
              'X-App': 'safe',
            },
            transport: stubTransport,
            maxRedirects: 0,
            proxy: false,
          });

          assert.ok(capturedHeaders, 'transport was not invoked');
          assert.strictEqual(capturedHeaders['X-App'], 'safe');
          assert.strictEqual(
            capturedHeaders.Authorization || capturedHeaders.authorization,
            'Bearer VALID_USER_TOKEN'
          );
          assert.strictEqual(response.headers.get('x-server'), 'real');
        } finally {
          delete Object.prototype[Symbol.toStringTag];
        }
      });
    });
  });

  // GHSA-9fr6-4gfg-395g, GHSA-j8rh-479h-cp32 and GHSA-vh66-26gq-q6x8: request
  // behavior must not be resolved from values that are inherited only through
  // a shared prototype — default-instance fallbacks, interceptor replacement
  // configs, Node transport options, toFormData options and fetch options.
  describe('runtime option handling', function () {
    function okResponse(data, config) {
      return {
        data,
        status: 200,
        statusText: 'OK',
        headers: {},
        config,
      };
    }

    describe('GHSA-9fr6-4gfg-395g default instance fallbacks', function () {
      it('should use GET when the default instance has no own method', async function () {
        Object.prototype.method = 'DELETE';

        const response = await axios({
          url: '/default-method',
          adapter: async (config) => okResponse(config.method, config),
        });

        assert.strictEqual(response.data, 'get');
      });

      it('should send GET on the wire for axios.request without a method', async function () {
        this.timeout(10000);

        const methods = [];
        const server = await startServer(function (req, res) {
          methods.push(req.method);
          res.end('ok');
        });

        Object.prototype.method = 'DELETE';

        try {
          const response = await axios.request({ url: serverURL(server) + '/resource', proxy: false });

          assert.strictEqual(response.data, 'ok');
          assert.deepStrictEqual(methods, ['GET']);
        } finally {
          delete Object.prototype.method;
          await stopServer(server);
        }
      });

      it('should keep absolute URLs absolute when allowAbsoluteUrls is only inherited', async function () {
        this.timeout(10000);

        let baseHits = 0;
        let targetHits = 0;

        const base = await startServer(function (req, res) {
          baseHits += 1;
          res.end('base');
        });
        const target = await startServer(function (req, res) {
          targetHits += 1;
          res.end('target');
        });

        Object.prototype.allowAbsoluteUrls = false;

        try {
          const response = await axios.request({
            baseURL: serverURL(base),
            url: serverURL(target) + '/resource',
            proxy: false,
          });

          assert.strictEqual(response.data, 'target');
          assert.strictEqual(response.config.allowAbsoluteUrls, true);
          assert.strictEqual(baseHits, 0, 'polluted allowAbsoluteUrls must not reroute through baseURL');
          assert.strictEqual(targetHits, 1);
        } finally {
          delete Object.prototype.allowAbsoluteUrls;
          await stopServer(base);
          await stopServer(target);
        }
      });
    });

    describe('GHSA-j8rh-479h-cp32 interceptor replacement configs', function () {
      it('should not send headers inherited after a minimal interceptor replacement', async function () {
        this.timeout(10000);

        const server = await startServer(function (req, res) {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ poisoned: req.headers['x-poisoned'] === undefined ? null : req.headers['x-poisoned'] }));
        });

        Object.prototype.headers = { 'X-Poisoned': 'yes' };

        try {
          const instance = axios.create();

          instance.interceptors.request.use(function (config) {
            return { url: config.url, method: config.method, timeout: 5000, proxy: false };
          });

          const response = await instance.get(serverURL(server) + '/minimal');
          const data = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;

          assert.deepStrictEqual(data, { poisoned: null });
        } finally {
          delete Object.prototype.headers;
          await stopServer(server);
        }
      });

      it('should ignore headers inherited after a request interceptor replaces config', async function () {
        Object.prototype.headers = { 'X-Injected': 'yes' };

        const instance = axios.create({
          adapter: async (config) => okResponse(config.headers.get('X-Injected'), config),
        });

        instance.interceptors.request.use((config) => {
          const replacement = { ...config };
          delete replacement.headers;
          return replacement;
        });

        const response = await instance.get('/interceptor-headers');

        assert.strictEqual(response.data, undefined);
      });

      it('should ignore behavior inherited after a request interceptor replaces config', async function () {
        let requestTransformCalled = false;
        let responseTransformCalled = false;

        Object.prototype.transformRequest = () => {
          requestTransformCalled = true;
        };
        Object.prototype.transformResponse = () => {
          responseTransformCalled = true;
        };
        Object.prototype.cancelToken = {
          throwIfRequested() {
            throw new Error('unexpected inherited cancelToken');
          },
        };
        Object.prototype.signal = { aborted: true };
        Object.prototype.method = 'delete';

        const instance = axios.create({
          adapter: async (config) => okResponse(config.method, config),
        });

        instance.interceptors.request.use((config) => {
          const replacement = { ...config };
          delete replacement.transformRequest;
          delete replacement.transformResponse;
          delete replacement.cancelToken;
          delete replacement.signal;
          delete replacement.method;
          return replacement;
        });

        const response = await instance.get('/interceptor-behavior');

        assert.strictEqual(requestTransformCalled, false);
        assert.strictEqual(responseTransformCalled, false);
        assert.strictEqual(response.data, undefined);
      });

      it('should ignore an adapter inherited after a request interceptor replaces config', async function () {
        let called = false;

        Object.prototype.adapter = async (config) => {
          called = true;
          return okResponse('unexpected', config);
        };

        const instance = axios.create();

        instance.interceptors.request.use((config) => {
          const replacement = { ...config };
          delete replacement.adapter;
          return replacement;
        });

        // 'safe' in base64 (this fromDataURI requires a ;-delimited media type)
        const response = await instance.get('data:text/plain;base64,c2FmZQ==', {
          responseType: 'text',
        });

        assert.strictEqual(called, false);
        assert.strictEqual(response.data, 'safe');
      });

      it('should preserve config inherited from a non-shared prototype after interception', async function () {
        const instance = axios.create();

        instance.interceptors.request.use((config) => {
          const replacement = Object.create({
            adapter: async (resolvedConfig) => okResponse(resolvedConfig.customValue, resolvedConfig),
            customValue: 'preserved',
          });

          replacement.url = config.url;
          replacement.method = config.method;
          replacement.headers = config.headers;

          return replacement;
        });

        const response = await instance.get('/prototype-template');

        assert.strictEqual(response.data, 'preserved');
      });

      [
        ['unchanged', ''],
        ['set to null', 'Object.prototype.constructor = null;'],
        ['deleted', 'delete Object.prototype.constructor;'],
        [
          'replaced by an accessor',
          `Object.defineProperty(Object.prototype, 'constructor', {
            configurable: true,
            get() { return Object; }
          });`,
        ],
      ].forEach(function ([description, mutateConstructor]) {
        it(`should exclude a foreign realm Object.prototype with its constructor ${description}`, async function () {
          const context = vm.createContext({
            adapter: async (config) => okResponse(config.customValue, config),
          });

          const replacement = vm.runInContext(
            `
              Object.prototype.transformResponse = () => 'polluted';
              ${mutateConstructor}
              Object.create({adapter, customValue: 'preserved'});
            `,
            context
          );

          const instance = axios.create();

          instance.interceptors.request.use((config) => {
            replacement.url = config.url;
            replacement.method = config.method;
            replacement.headers = config.headers;

            return replacement;
          });

          const response = await instance.get('/cross-realm-prototype-template');

          assert.strictEqual(response.data, 'preserved');
        });
      });
    });

    describe('dispatch config compatibility', function () {
      it('should preserve an unchanged merged config through dispatch', async function () {
        let interceptedConfig;
        let adapterConfig;

        const instance = axios.create({
          adapter: async (config) => {
            adapterConfig = config;
            return okResponse('ok', config);
          },
        });

        instance.interceptors.request.use((config) => {
          interceptedConfig = config;
          return config;
        });

        const response = await instance.get('/config-identity');

        assert.strictEqual(adapterConfig, interceptedConfig);
        assert.strictEqual(response.config, interceptedConfig);
        assert.strictEqual(Object.getPrototypeOf(adapterConfig), null);
        assert.strictEqual(
          Object.prototype.propertyIsEnumerable.call(adapterConfig, 'hasOwnProperty'),
          false
        );
        assert.strictEqual(Object.keys(adapterConfig).includes('hasOwnProperty'), false);
      });

      it('should materialize a frozen null-prototype interceptor replacement', async function () {
        let replacement;

        const instance = axios.create({
          adapter: async (config) => okResponse('ok', config),
        });

        instance.interceptors.request.use((config) => {
          replacement = Object.freeze(Object.assign(Object.create(null), config));
          return replacement;
        });

        const response = await instance.get('/frozen-replacement');

        assert.strictEqual(response.data, 'ok');
        assert.notStrictEqual(response.config, replacement);
        assert.strictEqual(Object.getPrototypeOf(response.config), null);
        assert.strictEqual(Object.isFrozen(response.config), false);
      });

      it('should filter unsafe keys from a null-prototype interceptor replacement', async function () {
        let replacement;

        const instance = axios.create({
          adapter: async (config) => okResponse({
            safe: config.safe,
            hasProto: Object.prototype.hasOwnProperty.call(config, '__proto__'),
            hasConstructor: Object.prototype.hasOwnProperty.call(config, 'constructor'),
            hasPrototype: Object.prototype.hasOwnProperty.call(config, 'prototype'),
          }, config),
        });

        instance.interceptors.request.use((config) => {
          replacement = Object.assign(Object.create(null), config);
          replacement.safe = 'preserved';
          Object.defineProperty(replacement, '__proto__', {
            value: 'excluded',
            enumerable: true,
            configurable: true,
            writable: true,
          });
          replacement.constructor = 'excluded';
          replacement.prototype = 'excluded';
          return replacement;
        });

        const response = await instance.get('/unsafe-own-keys');

        assert.deepStrictEqual(response.data, {
          safe: 'preserved',
          hasProto: false,
          hasConstructor: false,
          hasPrototype: false,
        });
        assert.notStrictEqual(response.config, replacement);
      });

      it('should normalize a class-based interceptor replacement', async function () {
        let replacement;

        class ConfigTemplate {
          marker() {
            return 'template';
          }
        }

        const instance = axios.create({
          adapter: async (config) => okResponse(config.marker(), config),
        });

        instance.interceptors.request.use((config) => {
          replacement = new ConfigTemplate();
          replacement.url = config.url;
          replacement.method = config.method;
          replacement.headers = config.headers;
          replacement.adapter = config.adapter;
          return replacement;
        });

        const response = await instance.get('/normalized-replacement');

        assert.strictEqual(response.data, 'template');
        assert.notStrictEqual(response.config, replacement);
        assert.strictEqual(response.config instanceof ConfigTemplate, false);
        assert.strictEqual(Object.getPrototypeOf(response.config), null);
        assert.strictEqual(Object.prototype.hasOwnProperty.call(response.config, 'marker'), true);
      });
    });

    describe('utils.toSafeFlatObject / terminal prototype boundaries', function () {
      it('should stop safe prototype flattening on cyclic Proxy prototypes', function () {
        let calls = 0;
        const proxy = new Proxy({}, {
          getPrototypeOf() {
            calls += 1;
            if (calls > 1) {
              throw new Error('cycled');
            }
            return proxy;
          },
        });

        assert.deepStrictEqual(Object.keys(utils.toSafeFlatObject(proxy)), []);
        assert.strictEqual(calls, 1);
      });

      it('should preserve null-prototype sources but exclude terminal templates', function () {
        const root = Object.create(null);
        root.own = 'preserved';

        assert.strictEqual(utils.getSafeProp(root, 'own'), 'preserved');
        assert.strictEqual(utils.toSafeFlatObject(root), root);

        const template = Object.create(null);
        template.inherited = 'excluded';

        const source = Object.create(template);
        source.own = 'preserved';

        assert.strictEqual(utils.getSafeProp(source, 'own'), 'preserved');
        assert.strictEqual(utils.getSafeProp(source, 'inherited'), undefined);

        const flattened = utils.toSafeFlatObject(source);

        assert.strictEqual(flattened.own, 'preserved');
        assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'inherited'), false);
      });

      it('should materialize immutable null-prototype sources', function () {
        const source = Object.freeze(Object.assign(Object.create(null), { own: 'preserved' }));
        const flattened = utils.toSafeFlatObject(source);

        assert.notStrictEqual(flattened, source);
        assert.strictEqual(Object.getPrototypeOf(flattened), null);
        assert.strictEqual(flattened.own, 'preserved');
        assert.strictEqual(Object.isFrozen(flattened), false);
      });

      it('should materialize and filter unsafe keys from null-prototype sources', function () {
        const source = Object.create(null);
        source.safe = 'preserved';
        Object.defineProperty(source, '__proto__', {
          value: 'excluded',
          enumerable: true,
          configurable: true,
          writable: true,
        });
        source.constructor = 'excluded';
        source.prototype = 'excluded';

        const flattened = utils.toSafeFlatObject(source);

        assert.notStrictEqual(flattened, source);
        assert.strictEqual(flattened.safe, 'preserved');
        assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, '__proto__'), false);
        assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'constructor'), false);
        assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'prototype'), false);
      });

      it('should exclude symbols inherited from terminal null-prototype templates', function () {
        const behavior = Symbol('behavior');
        const template = Object.create(null);
        template[behavior] = () => 'excluded';

        const source = Object.create(template);
        const flattened = utils.toSafeFlatObject(source);

        assert.strictEqual(utils.getSafeProp(source, behavior), undefined);
        assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, behavior), false);
      });

      it('should drop Object.prototype members but keep class members when flattening', function () {
        Object.prototype.polluted = 'attacker';

        class Template {
          method() {
            return 'class';
          }
        }

        const source = new Template();
        source.own = 'own';

        const flattened = utils.toSafeFlatObject(source);

        assert.strictEqual(Object.getPrototypeOf(flattened), null);
        assert.strictEqual(flattened.own, 'own');
        assert.strictEqual(flattened.method(), 'class');
        assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'polluted'), false);
        assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'constructor'), false);
      });
    });

    describe('http adapter createConnection', function () {
      it('should pass an own inert createConnection option to transports', async function () {
        this.timeout(10000);

        Object.prototype.createConnection = () => {
          throw new Error('unexpected inherited createConnection');
        };

        const server = http.createServer((req, res) => res.end('ok'));
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

        try {
          const response = await axios.get(`http://127.0.0.1:${server.address().port}/`, {
            proxy: false,
            transport: {
              request(options, handleResponse) {
                assert.strictEqual(
                  Object.prototype.hasOwnProperty.call(options, 'createConnection'),
                  true
                );
                assert.strictEqual(options.createConnection, undefined);
                return http.request(options, handleResponse);
              },
            },
          });

          assert.strictEqual(response.data, 'ok');
        } finally {
          delete Object.prototype.createConnection;
          await stopServer(server);
        }
      });

      [0, 5].forEach(function (maxRedirects) {
        it('should not open sockets through an inherited createConnection (maxRedirects ' + maxRedirects + ')', async function () {
          this.timeout(10000);

          let hijacked = 0;
          const server = await startServer(function (req, res) {
            res.end('ok');
          });

          Object.prototype.createConnection = function () {
            hijacked += 1;
            throw new Error('socket hijacked through Object.prototype.createConnection');
          };

          try {
            const response = await axios.get(serverURL(server) + '/', {
              proxy: false,
              maxRedirects,
            });

            assert.strictEqual(response.data, 'ok');
            assert.strictEqual(hijacked, 0);
          } finally {
            delete Object.prototype.createConnection;
            await stopServer(server);
          }
        });
      });
    });

    describe('GHSA-vh66-26gq-q6x8 fetch adapter', function () {
      let probeId = 0;

      before(function () {
        if (typeof fetch !== 'function' || typeof Request !== 'function') {
          this.skip();
        }
      });

      function swapGlobal(name, value) {
        const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);

        Object.defineProperty(globalThis, name, {
          value,
          writable: true,
          configurable: true,
          enumerable: false,
        });

        return function restore() {
          if (descriptor) {
            Object.defineProperty(globalThis, name, descriptor);
          } else {
            delete globalThis[name];
          }
        };
      }

      function startHeaderEcho() {
        return startServer(function (req, res) {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({
            good: req.headers['x-good'] === undefined ? null : req.headers['x-good'],
            authorization: req.headers.authorization === undefined ? null : req.headers.authorization,
          }));
        });
      }

      [
        ['an empty', () => ({})],
        ['a non-empty', () => ({ cache: 'no-store' })],
      ].forEach(function ([description, makeFetchOptions]) {
        it(`should not let inherited headers replace request headers with ${description} fetchOptions object`, async function () {
          this.timeout(10000);

          const server = await startHeaderEcho();

          Object.prototype.headers = { Authorization: 'Bearer POLLUTED' };

          try {
            const response = await axios.get(serverURL(server) + '/', {
              adapter: 'fetch',
              headers: { 'X-Good': 'yes' },
              fetchOptions: makeFetchOptions(),
            });

            assert.deepStrictEqual(response.data, { good: 'yes', authorization: null });
          } finally {
            delete Object.prototype.headers;
            await stopServer(server);
          }
        });
      });

      it('should send the resolved method on the wire when method is inherited', async function () {
        this.timeout(10000);

        const methods = [];
        const server = await startServer(function (req, res) {
          methods.push(req.method);
          res.end('ok');
        });

        Object.prototype.method = 'DELETE';

        try {
          const response = await axios.get(serverURL(server) + '/resource', { adapter: 'fetch' });

          assert.strictEqual(response.data, 'ok');
          assert.deepStrictEqual(methods, ['GET']);
        } finally {
          delete Object.prototype.method;
          await stopServer(server);
        }
      });

      it('should follow redirects on the wire when redirect is inherited', async function () {
        this.timeout(10000);

        const server = await startServer(function (req, res) {
          if (req.url === '/start') {
            res.statusCode = 302;
            res.setHeader('Location', '/final');
            res.end();
            return;
          }

          res.end('followed');
        });

        Object.prototype.redirect = 'error';

        try {
          const response = await axios.get(serverURL(server) + '/start', { adapter: 'fetch' });

          assert.strictEqual(response.data, 'followed');
        } finally {
          delete Object.prototype.redirect;
          await stopServer(server);
        }
      });

      it('should ignore Request options inherited only from Object.prototype', async function () {
        let captured;
        const restoreFetch = swapGlobal('fetch', function (input) {
          captured = input;
          return Promise.resolve(new Response('ok'));
        });

        Object.prototype.cache = 'no-store';
        Object.prototype.redirect = 'manual';

        try {
          const response = await axios.get('http://127.0.0.1:1/safe-request-options', {
            adapter: 'fetch',
          });

          assert.strictEqual(response.data, 'ok');
          assert.ok(captured instanceof Request);
          assert.strictEqual(captured.cache, 'default');
          assert.strictEqual(captured.redirect, 'follow');
        } finally {
          delete Object.prototype.cache;
          delete Object.prototype.redirect;
          restoreFetch();
        }
      });

      it('should not fail when Request mode and body are inherited from Object.prototype', async function () {
        let captured;
        const restoreFetch = swapGlobal('fetch', function (input) {
          captured = input;
          return Promise.resolve(new Response('ok'));
        });

        Object.prototype.mode = 'navigate';
        Object.prototype.body = 'unexpected GET body';

        try {
          const response = await axios.get('http://127.0.0.1:1/polluted-mode', {
            adapter: 'fetch',
          });

          assert.strictEqual(response.data, 'ok');
          assert.strictEqual(captured.mode, 'cors');
          assert.strictEqual(captured.body, null);
        } finally {
          delete Object.prototype.mode;
          delete Object.prototype.body;
          restoreFetch();
        }
      });

      it('should pass a fully resolved Request and safe options to fetch', async function () {
        let captured;
        const fetchOptions = Object.create({
          headers: {
            'X-Injected': 'yes',
          },
        });
        fetchOptions.cache = 'no-store';
        fetchOptions.redirect = 'error';
        fetchOptions.customOption = 'custom-value';
        fetchOptions.credentials = 'omit';
        fetchOptions.duplex = 'full';

        const restoreFetch = swapGlobal('fetch', function (input, init) {
          captured = {
            input,
            init,
            argumentCount: arguments.length,
          };
          return Promise.resolve(new Response('ok'));
        });

        try {
          const response = await axios.get('http://127.0.0.1:1/custom-fetch', {
            adapter: 'fetch',
            headers: {
              'X-Safe': 'value',
            },
            withCredentials: true,
            fetchOptions,
          });

          assert.strictEqual(response.data, 'ok');
          assert.ok(captured.input instanceof Request);
          assert.strictEqual(captured.input.headers.get('X-Safe'), 'value');
          assert.strictEqual(captured.input.headers.get('X-Injected'), null);
          assert.strictEqual(captured.input.cache, 'no-store');
          assert.strictEqual(captured.input.redirect, 'error');
          assert.strictEqual(captured.input.credentials, 'include');
          // fetch() receives own-property options that mirror the resolved
          // Request, so the runtime has nothing left to read from a prototype
          assert.strictEqual(Object.getPrototypeOf(captured.init), null);
          assert.strictEqual(captured.init.cache, 'no-store');
          assert.strictEqual(captured.init.redirect, 'error');
          assert.strictEqual(captured.init.customOption, 'custom-value');
          assert.strictEqual(captured.init.method, 'GET');
          assert.strictEqual(captured.init.body, null);
          assert.strictEqual(captured.init.signal, null);
          assert.strictEqual(captured.init.credentials, 'include');
          assert.strictEqual(captured.init.duplex, 'half');
          assert.strictEqual(captured.init.headers, captured.input.headers);
          assert.strictEqual(captured.argumentCount, 2);
        } finally {
          restoreFetch();
        }
      });

      async function requestWithRuntime(RequestImpl, config, onFetch) {
        const restoreRequest = swapGlobal('Request', RequestImpl);
        const restoreFetch = swapGlobal('fetch', function (input, init) {
          onFetch && onFetch(input, init);
          return Promise.resolve(new Response('ok'));
        });

        try {
          // a fresh module instance runs its Request capability probes against
          // the substituted runtime
          probeId += 1;
          const { default: fetchAdapter } = await import(
            '../../../lib/adapters/fetch.js?request-runtime=' + probeId
          );

          return await axios.get(
            'http://127.0.0.1:1/runtime',
            Object.assign({ adapter: fetchAdapter }, config)
          );
        } finally {
          restoreFetch();
          restoreRequest();
        }
      }

      [false, true].forEach(function (polluted) {
        it(`should omit cache when the runtime rejects every explicit mode${polluted ? ' with polluted options' : ''}`, async function () {
          const NativeRequest = Request;
          let capturedInit;

          class CacheDisabledRequest extends NativeRequest {
            constructor(input, init) {
              if (init && init.cache !== undefined) {
                throw new TypeError("The 'cache' field on 'RequestInitializerDict' is not implemented.");
              }

              super(input, init);
              capturedInit = init;
            }
          }

          try {
            if (polluted) {
              Object.prototype.cache = 'default';
            }

            const response = await requestWithRuntime(CacheDisabledRequest, {});

            assert.strictEqual(response.data, 'ok');
            assert.strictEqual(Object.getPrototypeOf(capturedInit), null);
            assert.strictEqual(Object.prototype.hasOwnProperty.call(capturedInit, 'cache'), false);
            assert.strictEqual(capturedInit.mode, 'cors');
            assert.strictEqual(capturedInit.redirect, 'follow');
          } finally {
            delete Object.prototype.cache;
          }
        });
      });

      it('should omit the default cache mode when the runtime rejects it', async function () {
        const NativeRequest = Request;
        let capturedCache = 'unset';

        class RestrictedCacheRequest extends NativeRequest {
          constructor(input, init) {
            capturedCache = init && init.cache;

            if (capturedCache !== undefined && capturedCache !== 'no-store') {
              throw new TypeError('Unsupported cache mode: ' + capturedCache);
            }

            super(input, init);
          }
        }

        let seenRedirect;

        const response = await requestWithRuntime(RestrictedCacheRequest, {}, function (input) {
          seenRedirect = input.redirect;
        });

        assert.strictEqual(response.data, 'ok');
        assert.strictEqual(capturedCache, undefined);
        assert.strictEqual(seenRedirect, 'follow');
      });

      it('should preserve an explicit supported cache option on a restricted runtime', async function () {
        const NativeRequest = Request;

        class RestrictedCacheRequest extends NativeRequest {
          constructor(input, init) {
            if (init && init.cache !== undefined && init.cache !== 'no-store' && init.cache !== 'no-cache') {
              throw new TypeError('Unsupported cache mode: ' + init.cache);
            }

            super(input, init);
          }
        }

        let seen;

        const response = await requestWithRuntime(
          RestrictedCacheRequest,
          { fetchOptions: { cache: 'no-store' } },
          function (input, init) {
            seen = { input: input.cache, init: init.cache };
          }
        );

        assert.strictEqual(response.data, 'ok');
        assert.deepStrictEqual(seen, { input: 'no-store', init: 'no-store' });
      });
    });
  });

});
