import * as assert from 'assert';
import { it, describe } from 'mocha';
import { validateWorkflowJsonInput } from '../../commands/workflow/utils';

suite('RunWorkflowCommand Test Suite', () => {
	describe('validateWorkflowJsonInput', () => {
		describe('valid inputs', () => {
			const validTests = [
				{ args: '', description: 'empty string (no input)' },
				{ args: '{}', description: 'empty JSON object' },
				{ args: '{"key":"value"}', description: 'simple JSON object' },
				{ args: '{"nested":{"a":1}}', description: 'nested JSON object' },
				{ args: '[]', description: 'empty JSON array' },
				{ args: '[1,2,3]', description: 'JSON array with numbers' },
				{ args: '"hello"', description: 'JSON string' },
				{ args: '42', description: 'JSON number' },
				{ args: 'true', description: 'JSON boolean' },
				{ args: 'null', description: 'JSON null' },
			];
			validTests.forEach(({ args, description }) => {
				it(`should return undefined for ${description}`, () => {
					const result = validateWorkflowJsonInput(args);
					assert.strictEqual(result, undefined);
				});
			});
		});

		describe('invalid inputs', () => {
			const invalidTests = [
				{ args: '{invalid}', description: 'malformed object' },
				{ args: '{key:value}', description: 'unquoted keys' },
				{ args: "{'key':'value'}", description: 'single-quoted keys' },
				{ args: 'undefined', description: 'undefined literal' },
				{ args: '{', description: 'unclosed brace' },
				{ args: '[1,2,', description: 'unclosed array' },
			];
			invalidTests.forEach(({ args, description }) => {
				it(`should return 'Invalid JSON' for ${description}`, () => {
					const result = validateWorkflowJsonInput(args);
					assert.strictEqual(result, 'Invalid JSON');
				});
			});
		});
	});
});
