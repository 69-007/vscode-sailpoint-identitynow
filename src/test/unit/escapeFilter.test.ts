import * as assert from 'assert';
import { it, describe, suite } from '../ava-bdd';
import { escapeFilter } from '../../utils/stringUtils';

suite('escapeFilter Test Suite', () => {
	describe('escapeFilter', () => {
		const tests = [
			{ args: '"Employees"', expected: '\\"Employees\\"' },
			{ args: undefined, expected: undefined },
		];
		tests.forEach(({ args, expected }) => {
			it(`should correctly escape ${args}`, () => {
				const result = escapeFilter(args);
				assert.strictEqual(result, expected);
			});
		});
	});

});
