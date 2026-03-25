/**
 * Validates the JSON input string for the workflow execution prompt.
 * Returns undefined when the value is acceptable, or an error message string when invalid.
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
 * Converts the raw input string from the workflow prompt into a payload object.
 * An empty string yields an empty object; any other string is parsed as JSON.
 */
export function buildWorkflowPayload(inputStr: string): object {
    return inputStr === '' ? {} : JSON.parse(inputStr);
}
