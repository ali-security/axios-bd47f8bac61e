"use strict";

import assert from "assert";
import http from "http";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import httpAdapter from "../../../lib/adapters/http.js";
import axios from "../../../index.js";

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
});
