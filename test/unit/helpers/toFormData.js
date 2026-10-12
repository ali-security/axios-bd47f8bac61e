import assert from 'assert';
import toFormData from '../../../lib/helpers/toFormData.js';
import AxiosError from '../../../lib/core/AxiosError.js';
import AxiosURLSearchParams from '../../../lib/helpers/AxiosURLSearchParams.js';
import FormData from 'form-data';
import axios from '../../../index.js';

describe('helpers::toFormData', function () {
  const createFormDataSpy = function () {
    return {
      calls: [],
      append(key, value) {
        this.calls.push([key, value]);
      },
    };
  };

  describe('options inherited from Object.prototype', function () {
    afterEach(function () {
      delete Object.prototype.visitor;
      delete Object.prototype.maxDepth;
    });

    it('should ignore a visitor inherited only from Object.prototype', function () {
      let called = false;
      Object.prototype.visitor = function () {
        called = true;
        return false;
      };

      try {
        const formData = createFormDataSpy();
        toFormData({ field: 'value' }, formData);

        assert.strictEqual(called, false);
        assert.deepStrictEqual(formData.calls, [['field', 'value']]);
      } finally {
        delete Object.prototype.visitor;
      }
    });

    it('should ignore maxDepth inherited only from Object.prototype', function () {
      Object.prototype.maxDepth = 0;

      try {
        const formData = createFormDataSpy();
        assert.doesNotThrow(() => toFormData({ nested: { field: 'value' } }, formData));
        assert.deepStrictEqual(formData.calls, [['nested[field]', 'value']]);
      } finally {
        delete Object.prototype.maxDepth;
      }
    });

    it('should ignore an inherited visitor when an options object without one is passed', function () {
      let called = false;
      Object.prototype.visitor = function () {
        called = true;
        this.append('injected', 'yes');
        return false;
      };

      try {
        const formData = createFormDataSpy();
        toFormData({ nested: { field: 'value' } }, formData, { dots: true });

        assert.strictEqual(called, false);
        assert.deepStrictEqual(formData.calls, [['nested.field', 'value']]);
      } finally {
        delete Object.prototype.visitor;
      }
    });

    it('should still honor own visitor and maxDepth options', function () {
      const seen = [];
      const formData = createFormDataSpy();

      toFormData({ field: 'value' }, formData, {
        visitor(value, key) {
          seen.push([key, value]);
          return false;
        },
      });

      assert.deepStrictEqual(seen, [['field', 'value']]);
      assert.deepStrictEqual(formData.calls, []);

      assert.throws(
        () => toFormData({ nested: { field: 'value' } }, createFormDataSpy(), { maxDepth: 0 }),
        (err) => err instanceof AxiosError && err.code === 'ERR_FORM_DATA_DEPTH_EXCEEDED'
      );
    });

    it('should not let an inherited visitor rewrite multipart request bodies', async function () {
      class SpyFormData {
        constructor() {
          this.calls = [];
        }

        append(key, value) {
          this.calls.push([key, value]);
        }
      }

      let called = false;
      Object.prototype.visitor = function () {
        called = true;
        this.append('injected', 'yes');
        return false;
      };

      try {
        let sentData;

        await axios.post(
          'http://localhost/upload',
          { field: 'value' },
          {
            headers: { 'Content-Type': 'multipart/form-data' },
            env: { FormData: SpyFormData },
            adapter(config) {
              sentData = config.data;

              return Promise.resolve({
                data: null,
                status: 200,
                statusText: 'OK',
                headers: {},
                config,
                request: {},
              });
            },
          }
        );

        assert.strictEqual(called, false);
        assert.ok(sentData instanceof SpyFormData);
        assert.deepStrictEqual(sentData.calls, [['field', 'value']]);
      } finally {
        delete Object.prototype.visitor;
      }
    });
  });

  // --- Depth limit tests ---

  function nest(depth) {
    let o = { leaf: 1 };
    for (let i = 0; i < depth; i++) o = { a: o };
    return o;
  }

  describe('maxDepth option', function () {
    it('should throw AxiosError when payload exceeds default depth limit (100)', function () {
      try {
        toFormData(nest(101), new FormData());
        assert.fail('Should have thrown');
      } catch (err) {
        assert.ok(err instanceof AxiosError, 'error must be AxiosError, not RangeError');
        assert.strictEqual(err.code, 'ERR_FORM_DATA_DEPTH_EXCEEDED');
        assert.ok(!(err instanceof RangeError));
      }
    });

    it('should succeed when payload is exactly at the default depth limit (100)', function () {
      const formData = toFormData(nest(100), new FormData());
      assert.ok(formData instanceof FormData);
    });

    it('should succeed for a shallow payload (no regression)', function () {
      const formData = toFormData(nest(5), new FormData());
      assert.ok(formData instanceof FormData);
    });

    it('should allow deeper payloads when maxDepth is raised', function () {
      const formData = toFormData(nest(150), new FormData(), { maxDepth: 200 });
      assert.ok(formData instanceof FormData);
    });

    it('should reject shallower payloads when maxDepth is lowered', function () {
      try {
        toFormData(nest(10), new FormData(), { maxDepth: 5 });
        assert.fail('Should have thrown');
      } catch (err) {
        assert.ok(err instanceof AxiosError);
        assert.strictEqual(err.code, 'ERR_FORM_DATA_DEPTH_EXCEEDED');
      }
    });

    it('should not throw for depth guard when maxDepth is Infinity (guard disabled)', function () {
      const formData = toFormData(nest(500), new FormData(), { maxDepth: Infinity });
      assert.ok(formData instanceof FormData);
    });

    it('should still detect circular references when depth guard is active', function () {
      const data = { foo: 'bar' };
      data.self = data;
      try {
        toFormData(data, new FormData());
        assert.fail('Should have thrown');
      } catch (err) {
        assert.ok(
          err.message.includes('Circular reference detected'),
          'must be circular-ref error'
        );
        assert.ok(!(err instanceof AxiosError) || err.code !== 'ERR_FORM_DATA_DEPTH_EXCEEDED');
      }
    });

    it('depth limit error is catchable as AxiosError with correct code', function () {
      let caught;
      try {
        toFormData(nest(101), new FormData());
      } catch (err) {
        caught = err;
      }
      assert.ok(caught instanceof AxiosError);
      assert.strictEqual(caught.code, 'ERR_FORM_DATA_DEPTH_EXCEEDED');
      assert.ok(!(caught instanceof RangeError));
    });
  });

  describe('maxDepth — params serialization via AxiosURLSearchParams', function () {
    it('should throw AxiosError for deeply nested params object (default limit)', function () {
      try {
        new AxiosURLSearchParams(nest(101));
        assert.fail('Should have thrown');
      } catch (err) {
        assert.ok(err instanceof AxiosError);
        assert.strictEqual(err.code, 'ERR_FORM_DATA_DEPTH_EXCEEDED');
      }
    });

    it('should build query string for deep params when maxDepth is raised', function () {
      const params = new AxiosURLSearchParams(nest(150), { maxDepth: 200 });
      const qs = params.toString();
      assert.ok(typeof qs === 'string' && qs.length > 0);
    });
  });
});
