import { App, applyDocumentTheme, applyHostStyleVariables } from '@modelcontextprotocol/ext-apps';
import { OpenAIExtensions } from '@openai/mcp-extensions/app';
import { createPreviewClient } from './preview-client.js';
const previewClient = createPreviewClient();

const $ = id => document.getElementById(id);
const labels = {active:'Выполняется',pending:'Ожидает',blocked:'Заблокирована',unknown:'Требует проверки',complete:'Завершена по Seed',failed:'Не выполнена',CURRENT:'Актуально по источнику',STALE:'Устарело',UNKNOWN:'Не подтверждено',SUPERSEDED:'Заменено',CONTRADICTED:'Противоречие'};
let app, extensions, modelContext, projectData, taskData, pending = false, loadGeneration = 0;
let selection = {};
try { selection = JSON.parse(sessionStorage.getItem('integrity-selection') || '{}'); } catch {}
const preview = window.parent === window;
const el = (tag, text, cls) => { const node = document.createElement(tag); if(text != null) node.textContent = text; if(cls) node.className=cls; return node; };
function status(text='', error=false) { $('status').textContent=text; $('status').className='notice'+(error?' error':''); }
function save() { sessionStorage.setItem('integrity-selection', JSON.stringify(selection)); }
function pill(text,state){return el('span',text,'pill'+(state==='STALE'?' stale':['UNKNOWN','blocked','unknown'].includes(state)?' warn':''));}
async function call(name,args={}) {
  let result;
  if(preview) {
    result=await previewClient.call(name,args);
  } else result=await app.callServerTool({name,arguments:args});
  if(result.isError) { const error = new Error(result.structuredContent?.message || 'Источник недоступен. Обновите проект.'); error.code=result.structuredContent?.code; throw error; }
  return result.structuredContent;
}
function displayError(error) {if(preview&&error.code==='access_denied'){$('login').hidden=false;$('workspace').hidden=true;}status(error.code==='stale_snapshot'?error.message:error.message || 'Не удалось связаться с Integrity. Данные не обновлены.',true);}
function args(extra={}) {return {project_id:selection.project_id,snapshot_id:projectData.snapshot_id,...extra};}
function sourceButton(id) {const button=el('button',`Источник #${id}`,'link');button.type='button';button.onclick=async()=>{try{const source=await call('integrity_source',args({event_id:id}));$('sources').replaceChildren(el('h3','Канонический источник'),el('p',source.events[0]?.summary || 'Содержание не доступно.'),el('small',source.uri,'source'));$('sources').hidden=false;}catch(error){displayError(error);}};return button;}
function relationItem(link) {const block=el('div',null,'relation');block.append(el('div',link.neighbor.title),pill(labels[link.freshness?.state]||'Актуальность неизвестна',link.freshness?.state));const sources=el('div');for(const id of link.source_event_ids.slice(0,3)){sources.append(sourceButton(id),document.createTextNode(' '));}block.append(sources);return block;}
function card(title,links) {const node=el('section',null,'card');node.append(el('h3',title));if(!links.length) node.append(el('p','В выбранном источнике сведения отсутствуют.','muted'));for(const link of links)node.append(relationItem(link));return node;}
function relations(brief){return brief.relationships.groups.flatMap(group=>group.links);}
function renderProject() {
  $('sources').hidden=true;const view=$('view');view.replaceChildren(el('h2',projectData.project.label));
  const stats=Object.entries(projectData.status_counts).filter(([,count])=>count).map(([key,count])=>`${labels[key]}: ${count}`).join(' · ');
  $('counts').textContent=stats||'В проекте пока нет задач';
  $('tasks').replaceChildren();
  for(const task of projectData.tasks){const button=el('button',null,'task-card'+(task.task_id===selection.task_id?' active':''));button.append(el('strong',task.title||task.summary),pill(labels[task.status],task.status));button.onclick=()=>loadTask(task.task_id);$('tasks').append(button);}
  $('more').hidden=!projectData.pagination.has_more;
  if(!projectData.tasks.length)view.append(el('p','Этот проект пуст. Задачи появятся здесь после записи через Integrity.','empty'));
  const grid=el('div',null,'grid');grid.append(card('Решения проекта',projectData.decisions),card('Ограничения',projectData.constraints));view.append(grid);
    if(projectData.tasks.length)view.append(el('p','Выберите существующую задачу, чтобы увидеть её контекст и результаты.','muted'));
}
function renderTask() {
  const view=$('view');const brief=taskData.brief;const own=brief.tasks.cards.find(task=>task.task_id===selection.task_id);
  const links=relations(brief);view.replaceChildren(el('div',projectData.project.label,'label'),el('h2',brief.identity.title));
  view.append(pill(labels[own.status],own.status),el('p',own.scope||'Ограничения исполнения не указаны.','muted'));
  const actions=el('div',null,'actions');const attach=el('button','Передать контекст модели','primary');attach.id='attach-context';attach.disabled=preview||!modelContext||pending;
  attach.onclick=attachContext;actions.append(attach);const resume=el('button','Продолжить через исполнителя');resume.id='continue-task';resume.disabled=true;actions.append(resume);view.append(actions);
  view.append(el('p',preview?'В локальном браузере нет host-моста ChatGPT. Передача станет доступна после частного подключения.':!modelContext?'Этот host не поддерживает передачу контекста.': 'Будет передан ограниченный контекст только выбранной задачи.','muted'));
  const reason=el('div',taskData.continuation.reason,'notice');view.append(reason);
  const grid=el('div',null,'grid');grid.append(card('Решения и зависимости',links.filter(link=>['decision','task'].includes(link.neighbor.kind))),card('Ограничения и принципы',links.filter(link=>link.neighbor.kind==='concept')));view.append(grid);
  view.append(card('Результаты и свидетельства',links.filter(link=>link.neighbor.kind==='evidence')));
  const history=el('section',null,'card');history.append(el('h3','Последние сведения о задаче'));
  for(const event of brief.activity.events){const item=el('div',null,'relation');item.append(el('p',event.summary),el('small',event.ts_utc+' · '),sourceButton(event.event_id));history.append(item);}view.append(history);
  if(brief.unknowns.length)view.append(el('p','Часть сведений неполна или не имеет политики актуальности. Статус в Seed сам по себе не доказывает результат исполнителя.','muted'));
  const identity=el('details');identity.append(el('summary','Идентичность и источники'),el('p',`Проект: ${selection.project_id}\nЗадача: ${selection.task_id}\n${brief.identity.uri}`));view.append(identity);
}
async function attachContext(){if(pending||!modelContext||!taskData)return;pending=true;renderTask();try{const context=await call('integrity_context',args({task_id:selection.task_id}));if(context.task_id!==selection.task_id||context.project_id!==selection.project_id)throw new Error('Выбранная задача изменилась. Передача остановлена.');await modelContext.update({content:context.content,structuredContent:context.structuredContent});status(`Контекст задачи добавлен · ${context.byte_count} байт${context.truncated?' · некоторые ссылки не вошли в ограниченный пакет':''}.`);}catch(error){displayError(error);}finally{pending=false;if(taskData)renderTask();}}
async function loadTask(id){const generation=++loadGeneration;try{if(selection.task_id!==id&&modelContext)await modelContext.update({content:[],structuredContent:{}});selection.task_id=id;save();taskData=null;status('Загрузка задачи…');const data=await call('integrity_task',args({task_id:id}));if(generation!==loadGeneration)return;taskData=data;renderProject();renderTask();status();}catch(error){if(generation===loadGeneration)displayError(error);}}
async function loadProject(id,restore=true){++loadGeneration;selection.project_id=id;if(!restore)delete selection.task_id;save();taskData=null;status('Загрузка проекта…');$('view').replaceChildren();$('tasks').replaceChildren();$('counts').textContent='';$('sources').hidden=true;try{projectData=await call('integrity_project',{project_id:id});if(selection.project_id!==id)return;renderProject();status();if(restore&&selection.task_id)await loadTask(selection.task_id);}catch(error){displayError(error);}}
async function initialize(data){$('login').hidden=true;$('workspace').hidden=false;$('project').replaceChildren();for(const project of data.projects){const option=el('option',project.label);option.value=project.id;$('project').append(option);}if(!data.projects.length){$('view').replaceChildren(el('p','Для этого подключения нет проектов.','empty'));status();return;}const id=data.projects.some(p=>p.id===selection.project_id)?selection.project_id:data.projects[0].id;$('project').value=id;await loadProject(id);}
$('project').onchange=async()=>{try{if(modelContext)await modelContext.update({content:[],structuredContent:{}});await loadProject($('project').value,false);}catch(error){displayError(error);}};
$('refresh').onclick=()=>loadProject(selection.project_id);
$('more').onclick=async()=>{try{const next=await call('integrity_project',{project_id:selection.project_id,after_task_id:projectData.pagination.after_task_id});if(next.snapshot_id!==projectData.snapshot_id)throw new Error('Источник изменился. Обновите проект.');projectData.tasks.push(...next.tasks);projectData.pagination=next.pagination;renderProject();if(taskData)renderTask();}catch(error){displayError(error);}};
$('login-form').onsubmit=async event=>{event.preventDefault();const token=$('token').value;$('token').value='';try{const result=await previewClient.connect(token);if(result.isError)throw new Error('Источник не допустил чтение проекта.');await initialize(result.structuredContent);status();}catch(error){displayError(error);}};
async function start(){if(preview){$('login').hidden=false;return;}
  app=new App({name:'integrity-space',version:'0.2.0'});extensions=new OpenAIExtensions(app);
  function host(){const context=app.getHostContext();if(context?.theme)applyDocumentTheme(context.theme);if(context?.styles?.variables)applyHostStyleVariables(context.styles.variables);const attached=extensions.modelContext?.getCurrent()?.structuredContent;if(attached?.project_id&&attached?.task_id){selection={project_id:attached.project_id,task_id:attached.task_id};save();}}
  let connected=false, initialData;
  app.ontoolresult=result=>{if(result.structuredContent?.projects){if(connected)initialize(result.structuredContent).catch(displayError);else initialData=result.structuredContent;}};
  app.addEventListener('hostcontextchanged',host);await app.connect();modelContext=extensions.modelContext;host();connected=true;if(initialData)await initialize(initialData);
  // Entrypoint supplies initial data. Only restoration of canonical project/task reads follows it.
}
start().catch(displayError);
