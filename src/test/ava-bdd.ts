import type { ExecutionContext, TestFn } from 'ava';

const avaModule = require('ava') as { default?: TestFn };
const avaTest = avaModule.default as TestFn;
const contextStack: string[] = [];
const testTitleCount = new Map<string, number>();

function runBlock(callback: () => unknown): void {
	const maybePromise = callback();
	if (maybePromise && typeof (maybePromise as Promise<unknown>).then === 'function') {
		(maybePromise as Promise<unknown>).catch((error: unknown) => {
			throw error;
		});
	}
}

export function suite(name: string, callback: () => unknown): void {
	contextStack.push(name);
	try {
		runBlock(callback);
	} finally {
		contextStack.pop();
	}
}

export function describe(name: string, callback: () => unknown): void {
	contextStack.push(name);
	try {
		runBlock(callback);
	} finally {
		contextStack.pop();
	}
}

export function it(name: string, callback: (t: ExecutionContext) => unknown): void {
	const baseTitle = contextStack.length > 0 ? `${contextStack.join(' › ')} › ${name}` : name;
	const count = (testTitleCount.get(baseTitle) ?? 0) + 1;
	testTitleCount.set(baseTitle, count);
	const testTitle = count > 1 ? `${baseTitle} [${count}]` : baseTitle;

	avaTest(testTitle, async (t) => {
		await callback(t);
	});
}
