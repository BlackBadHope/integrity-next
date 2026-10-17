// Actual preview-client -> TestClient -> MCPServer -> SeedCatalog roundtrip.
// stdin/stdout are an in-memory test transport, with no listener or token logs.
import assert from 'node:assert/strict';
import {createInterface} from 'node:readline';
import {createPreviewClient} from '../ui/preview-client.js';
const input = createInterface({input:process.stdin});
const lines = input[Symbol.asyncIterator]();
const first = JSON.parse((await lines.next()).value);
const client = createPreviewClient(async (path, options) => {
  process.stdout.write(JSON.stringify({path, ...options})+'\n');
  const response = JSON.parse((await lines.next()).value);
  return {ok:response.status>=200&&response.status<300, status:response.status, json:async()=>response.data};
});
await assert.rejects(()=>client.connect('synthetic-invalid-local-code-at-least-32-characters'), error=>error.code==='access_denied');
await assert.rejects(()=>client.call('integrity_projects'), /код подключения/);
const bootstrap = await client.connect(first.token);
assert.equal(bootstrap.structuredContent.mode, 'isolated-lab');
const project = (await client.call('integrity_project', {project_id:'space-lab-interface'})).structuredContent;
assert.ok(project.tasks.length);
const task = (await client.call('integrity_task', {project_id:'space-lab-interface',task_id:'review-interface',snapshot_id:project.snapshot_id})).structuredContent;
assert.equal(task.task_id, 'review-interface');
const source = (await client.call('integrity_source', {project_id:'space-lab-interface',event_id:2,snapshot_id:project.snapshot_id})).structuredContent;
assert.equal(source.events[0].event_id, 2);
client.clear();
await assert.rejects(()=>client.call('integrity_projects'), /код подключения/);
process.stdout.write(JSON.stringify({done:true})+'\n');
input.close();
