import * as vscode from 'vscode';
import { WorkflowTreeItem } from '../../models/ISCTreeItem';
import { ISCClient } from '../../services/ISCClient';
import { TenantService } from '../../services/TenantService';
import { validateTenantReadonly } from '../validateTenantReadonly';
import { getWorkflowExecutionDetailUri } from '../../utils/UriUtils';
import { openPreview } from '../../utils/vsCodeHelpers';

export class RunWorkflowCommand {

    constructor(private readonly tenantService: TenantService) { }

    public async run(node: WorkflowTreeItem): Promise<void> {
        console.log("> runWorkflow", node);

        if (node === undefined || !(node instanceof WorkflowTreeItem)) {
            console.log("WARNING: runWorkflow: invalid item", node);
            throw new Error("runWorkflow: invalid item");
        }

        if (!(await validateTenantReadonly(this.tenantService, node.tenantId, `run workflow ${node.label}`))) {
            return;
        }

        const payloadStr = await vscode.window.showInputBox({
            prompt: 'Enter the JSON payload for the workflow trigger input (leave empty for no input)',
            placeHolder: '{}',
            value: '{}',
            validateInput: (value) => {
                if (value.trim() === '') {
                    return null;
                }
                try {
                    JSON.parse(value);
                    return null;
                } catch {
                    return 'Invalid JSON';
                }
            }
        });

        if (payloadStr === undefined) {
            console.log("< runWorkflow: cancelled by user");
            return;
        }

        const payload = payloadStr.trim() === '' ? {} : JSON.parse(payloadStr);

        const client = new ISCClient(node.tenantId, node.tenantName);

        const executionId = await vscode.window.withProgress<string>({
            location: vscode.ProgressLocation.Notification,
            title: `Running workflow ${node.label}...`,
            cancellable: false
        }, async () => {
            return await client.testWorkflow(node.resourceId, payload);
        });

        const action = await vscode.window.showInformationMessage(
            `Workflow ${node.label} started. Execution ID: ${executionId}`,
            'View execution details'
        );

        if (action === 'View execution details') {
            const uri = getWorkflowExecutionDetailUri(node.tenantName, executionId);
            openPreview(uri);
        }

        console.log("< runWorkflow");
    }
}
