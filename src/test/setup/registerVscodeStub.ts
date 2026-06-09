const Module = require('module') as {
	_load: (request: string, parent: unknown, isMain: boolean) => unknown;
};

const originalLoad = Module._load;

const vscodeStub = {
	workspace: {
		workspaceFolders: [],
		getConfiguration: () => ({
			get: () => undefined,
			inspect: () => undefined,
			update: () => Promise.resolve(undefined),
		}),
	},
	ConfigurationTarget: {
		WorkspaceFolder: 1,
		Workspace: 2,
		Global: 3,
	},
};

Module._load = function (request: string, parent: unknown, isMain: boolean) {
	if (request === 'vscode') {
		return vscodeStub;
	}

	return originalLoad(request, parent, isMain);
};
