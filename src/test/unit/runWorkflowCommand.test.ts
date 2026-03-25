import * as assert from 'assert';
import { it, describe } from 'mocha';
import { validateWorkflowInput, buildWorkflowPayload } from '../../commands/workflow/workflowInputUtils';

suite('RunWorkflowCommand Test Suite', () => {

    describe('validateWorkflowInput', () => {
        const tests: { should: string; input: string; expected: string | undefined }[] = [
            {
                should: 'accept an empty string',
                input: '',
                expected: undefined,
            },
            {
                should: 'accept a valid JSON object',
                input: '{"key":"value"}',
                expected: undefined,
            },
            {
                should: 'accept a valid JSON object with multiple fields',
                input: '{"name":"test","count":42}',
                expected: undefined,
            },
            {
                should: 'accept a valid JSON array',
                input: '[1,2,3]',
                expected: undefined,
            },
            {
                should: 'accept valid JSON null',
                input: 'null',
                expected: undefined,
            },
            {
                should: 'reject an unquoted bare word',
                input: 'notjson',
                expected: 'Invalid JSON',
            },
            {
                should: 'reject JSON with a trailing comma',
                input: '{"key":"value",}',
                expected: 'Invalid JSON',
            },
            {
                should: 'reject an unclosed brace',
                input: '{"key":"value"',
                expected: 'Invalid JSON',
            },
        ];

        tests.forEach(({ should, input, expected }) => {
            it(`should ${should}`, () => {
                const result = validateWorkflowInput(input);
                assert.strictEqual(result, expected);
            });
        });
    });

    describe('buildWorkflowPayload', () => {
        const tests: { should: string; input: string; expected: object }[] = [
            {
                should: 'return an empty object for an empty string',
                input: '',
                expected: {},
            },
            {
                should: 'parse a simple JSON object',
                input: '{"key":"value"}',
                expected: { key: 'value' },
            },
            {
                should: 'parse a nested JSON object',
                input: '{"outer":{"inner":1}}',
                expected: { outer: { inner: 1 } },
            },
            {
                should: 'parse a JSON array',
                input: '[1,2,3]',
                expected: [1, 2, 3],
            },
        ];

        tests.forEach(({ should, input, expected }) => {
            it(`should ${should}`, () => {
                const result = buildWorkflowPayload(input);
                assert.deepStrictEqual(result, expected);
            });
        });
    });

});
