import { WorkflowBeta } from "sailpoint-api-client";

/**
 * Validates a JSON string input for workflow execution.
 * Returns undefined if the value is valid (empty string or valid JSON),
 * or an error message string if the JSON is invalid.
 */
export function validateWorkflowJsonInput(value: string): string | undefined {
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