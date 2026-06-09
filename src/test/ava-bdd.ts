import type { TestFn } from 'ava';

const avaModule = require('ava') as { default?: TestFn };
const avaTest = avaModule.default as TestFn;
const contextStack: string[] = [];
const testTitleCount = new Map<string, number>();

export function suite(_name: string, callback: () => unknown): void {
	contextStack.push(_name);
	try {
		void callback();
	} finally {
		contextStack.pop();
	}
}

export function describe(_name: string, callback: () => unknown): void {
	contextStack.push(_name);
	try {
		void callback();
	} finally {
		contextStack.pop();
	}
}

export function it(name: string, callback: () => unknown): void {
	const baseTitle = contextStack.length > 0 ? `${contextStack.join(' › ')} › ${name}` : name;
	const count = (testTitleCount.get(baseTitle) ?? 0) + 1;
	testTitleCount.set(baseTitle, count);
	const testTitle = count > 1 ? `${baseTitle} [${count}]` : baseTitle;

	avaTest(testTitle, async (t) => {
		await callback();
		t.pass();
	});
}
