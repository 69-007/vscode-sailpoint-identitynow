import * as assert from 'assert';
import { it, describe } from 'mocha';
import { validateWorkflowInput, parseWorkflowPayload } from '../../commands/workflow/utils';

suite('RunWorkflowCommand Test Suite', () => {

    describe('validateWorkflowInput()', () => {
        it('should return undefined for an empty string (no input)', () => {
            assert.strictEqual(validateWorkflowInput(''), undefined);
        });

        it('should return undefined for a valid JSON object', () => {
            assert.strictEqual(validateWorkflowInput('{"key":"value"}'), undefined);
        });

        it('should return undefined for a valid JSON object with nested properties', () => {
            assert.strictEqual(validateWorkflowInput('{"input":{"id":"abc123","type":"IdentityMover"}}'), undefined);
        });

        it('should return undefined for a valid JSON array', () => {
            assert.strictEqual(validateWorkflowInput('[1,2,3]'), undefined);
        });

        it('should return undefined for a valid JSON string literal', () => {
            assert.strictEqual(validateWorkflowInput('"hello"'), undefined);
        });

        it('should return "Invalid JSON" for plain text', () => {
            assert.strictEqual(validateWorkflowInput('not json'), 'Invalid JSON');
        });

        it('should return "Invalid JSON" for a partial object', () => {
            assert.strictEqual(validateWorkflowInput('{key:value}'), 'Invalid JSON');
        });

        it('should return "Invalid JSON" for unclosed braces', () => {
            assert.strictEqual(validateWorkflowInput('{"key":"value"'), 'Invalid JSON');
        });
    });

    describe('parseWorkflowPayload()', () => {
        it('should return an empty object for an empty string', () => {
            assert.deepStrictEqual(parseWorkflowPayload(''), {});
        });

        it('should parse a simple JSON object', () => {
            assert.deepStrictEqual(parseWorkflowPayload('{"key":"value"}'), { key: 'value' });
        });

        it('should parse a nested JSON object', () => {
            assert.deepStrictEqual(
                parseWorkflowPayload('{"input":{"id":"abc123"}}'),
                { input: { id: 'abc123' } }
            );
        });

        it('should parse a JSON object with multiple fields', () => {
            assert.deepStrictEqual(
                parseWorkflowPayload('{"a":1,"b":true,"c":"hello"}'),
                { a: 1, b: true, c: 'hello' }
            );
        });
    });

});
