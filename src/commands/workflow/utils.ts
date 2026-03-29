import { WorkflowBeta } from "sailpoint-api-client";

/**
 * Validates JSON input for a workflow execution.
 * Returns undefined when the input is valid, or an error message string when it is invalid.
 * An empty string is treated as valid (no input).
 */
export function validateWorkflowInput(value: string): string | undefined {
    if (value === '') {
        return undefined;
    }
    try {
        JSON.parse(value);
        return undefined;
    } catch {
        return 'Invalid JSON';
    }
}

/**
 * Parses a workflow input string into a payload object.
 * An empty string produces an empty object `{}`.
 */
export function parseWorkflowPayload(inputStr: string): object {
    return inputStr === '' ? {} : JSON.parse(inputStr);
}

export function cleanUpWorkflow(workflow: WorkflowBeta): WorkflowBeta {
    let w = removeUnwantedProperties(workflow)
    w = removeSecret(w)
    return w
}

const propertiesToCleanUp = [
    "created", "creator", "modified", "modifiedBy", "owner"
]

export function removeUnwantedProperties(workflow: WorkflowBeta) {

    propertiesToCleanUp.forEach(p => delete workflow[p])
    return workflow
}

export function removeSecret(obj: any) {
    for (const prop in obj) {
        if (typeof obj[prop] === 'string' && obj[prop].startsWith("$.secrets.")) { obj[prop] = null; }
        else if (typeof obj[prop] === 'object') { removeSecret(obj[prop]); }
    }
    return obj;
}