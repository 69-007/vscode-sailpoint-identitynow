import * as vscode from 'vscode';
import { WorkflowTreeItem } from '../../models/ISCTreeItem';
import { ISCClient } from '../../services/ISCClient';
import { getWorkflowExecutionDetailUri } from '../../utils/UriUtils';
import { openPreview } from '../../utils/vsCodeHelpers';
import { TenantService } from '../../services/TenantService';
import { validateTenantReadonly } from '../validateTenantReadonly';
import { validateWorkflowInput, parseWorkflowPayload } from './utils';

export class RunWorkflowCommand {

    constructor(private readonly tenantService: TenantService) { }

    public async execute(node: WorkflowTreeItem): Promise<void> {
        console.log("> runWorkflow", node);
        if (node === undefined || !(node instanceof WorkflowTreeItem)) {
            console.log("WARNING: runWorkflow: invalid item", node);
            throw new Error("runWorkflow: invalid item");
        }

        if (!(await validateTenantReadonly(this.tenantService, node.tenantId, `run workflow ${node.label}`))) {
            return;
        }

        const inputStr = await vscode.window.showInputBox({
            prompt: 'Enter JSON input for the workflow (leave empty for no input)',
            placeHolder: '{}',
            validateInput: validateWorkflowInput
        });

        if (inputStr === undefined) {
            console.log("< runWorkflow: cancelled by user");
            return;
        }

        const payload = parseWorkflowPayload(inputStr);

        const client = new ISCClient(node.tenantId, node.tenantName);

        const executionId = await vscode.window.withProgress<string>({
            location: vscode.ProgressLocation.Notification,
            title: `Running workflow ${node.label}...`,
            cancellable: false
        }, async () => {
            return await client.testWorkflow(node.resourceId, payload);
        });

        await vscode.window.showInformationMessage(
            `Workflow ${node.label} started. Execution ID: ${executionId}`
        );

        const uri = getWorkflowExecutionDetailUri(node.tenantName, executionId);
        openPreview(uri);

        console.log("< runWorkflow");
    }
}
