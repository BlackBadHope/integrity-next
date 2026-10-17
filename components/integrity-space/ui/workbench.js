import { App, applyDocumentTheme, applyHostStyleVariables } from '@modelcontextprotocol/ext-apps';
import { OpenAIExtensions } from '@openai/mcp-extensions/app';
import { createPreviewClient } from './preview-client.js';
const previewClient = createPreviewClient();
import { READ_TOOLS, unpack, cleanText, normalizePage, mergePage, activity, safeLinks, readIdentity, mergeReadPages, contextSelection } from './workbench-model.js';
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const fmt=new Intl.DateTimeFormat('ru',{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
const timeFmt=new Intl.DateTimeFormat('ru',{hour:'2-digit',minute:'2-digit'});
let app,extensions,modelContext,hosts=[],tasks=[],pageCursor=null,selected=null,detail=null;
let hostId='',listGeneration=0,detailGeneration=0,pendingList=false,pendingRead=false,started=false,snapshot=false;
let lastRead=null,hasRead=false,snapshotAt=null,activeTab='overview',preview=window.parent===window;
let selection={};try{selection=JSON.parse(sessionStorage.getItem('integrity-workbench-selection')||'{}');}catch{}
const save=()=>{try{sessionStorage.setItem('integrity-workbench-selection',JSON.stringify({host_id:hostId,thread_id:selected?.id}));}catch{}};
function notice(text='',error=false){$('notice').textContent=cleanText(text);$('notice').className='notice'+(error?' error':'');}
function readStamp(date){return date?'Прочитано в '+timeFmt.format(date):'Время чтения неизвестно';}
function currentHost(){return hosts.find(h=>h.host_id===hostId);}
function callName(suffix){return currentHost()?.route==='desktop_cloud'?'codex_cloud_'+suffix:'codex_'+suffix;}
async function call(name,args={}){
  if(!READ_TOOLS.has(name))throw new Error('Эта панель поддерживает только чтение.');
  let result;
  try{result=preview?await previewClient.call(name,args):await app.callServerTool({name,arguments:args});}
  catch(error){if(preview&&error.code==='access_denied'){$('preview-login').hidden=false;document.querySelector('header').hidden=true;document.querySelector('main').hidden=true;started=false;}throw error;}
  return unpack(result);
}
function setTab(tab){activeTab=tab;for(const n of document.querySelectorAll('[data-tab]')){n.setAttribute('aria-selected',String(n.dataset.tab===tab));n.classList.toggle('active',n.dataset.tab===tab);}
  $('overview').hidden=tab!=='overview';$('browser').hidden=tab==='overview';$('results-intro').hidden=tab!=='results';
  renderList();
}
function updateButtons(){$('refresh').disabled=pendingList;$('search-submit').disabled=pendingList;$('host').disabled=pendingList;
  $('more').disabled=pendingList;$('read-more').disabled=pendingRead;$('reread').disabled=pendingRead||!selected;
  $('attach').disabled=!modelContext||!detail||pendingRead;
  $('copy-identity').disabled=!detail||pendingRead;
}
function draw(){
  $('total').textContent=hasRead?String(tasks.length):'—';
  const recent=tasks.filter(t=>t.updated&&Date.now()-t.updated<86400000&&Date.now()>=t.updated).length;
  $('recent').textContent=hasRead?String(recent):'—';
  const enabled=hosts.filter(h=>h.availability!=='disabled'&&h.route!=='disabled').length,disabled=hosts.length-enabled;
  const one=n=>n%10===1&&n%100!==11;
  $('sources-total').textContent=enabled+' '+(one(enabled)?'включён':'включены')+' · '+disabled+' '+(one(disabled)?'отключён':'отключены');
  $('freshness').textContent=(snapshot?'Снимок источника · ':'')+(hasRead?readStamp(lastRead):'Ещё не прочитано');
  $('coverage').textContent=pageCursor?'Показана часть списка · доступны следующие страницы':'Источник не вернул следующую страницу. Полнота всей истории не подтверждена.';
  $('host-label').textContent=currentHost()?.label||'Источник';
  $('more').hidden=!pageCursor;
  const days=activity(tasks),max=Math.max(1,...days.map(d=>d.count));$('activity').replaceChildren();
  for(const d of days){const item=el('div',undefined,'bar-item');const bar=el('div',undefined,'bar-track');const fill=el('div',undefined,'bar-fill');fill.style.height=(d.count/max*100)+'%';bar.append(fill);
    item.append(el('span',String(d.count),'bar-value'),bar,el('span',d.day.toLocaleDateString('ru',{weekday:'short'}),'bar-label'));
    item.setAttribute('aria-label',d.day.toLocaleDateString('ru')+': '+d.count);$('activity').append(item);}
  $('activity').setAttribute('aria-label','Распределение дат последнего изменения загруженных чатов за семь дней. Это не число сообщений.');
  $('source-list').replaceChildren();
  for(const h of hosts){const line=el('div',undefined,'source-row');const disabled=h.availability==='disabled'||h.route==='disabled';
    const copy=el('div');copy.append(el('strong',cleanText(h.label)),el('small',h.host_id));
    const b=el('button',disabled?'Отключён':h.host_id===hostId&&hasRead?(snapshot?'Есть снимок':'Прочитан'):'Открыть','source-action'+(disabled?' muted':''));
    b.disabled=disabled||pendingList;b.onclick=()=>{$('host').value=h.host_id;loadHost(h.host_id);};line.append(copy,b);$('source-list').append(line);}
  $('latest').replaceChildren();for(const task of tasks.slice(0,4)){const b=el('button',undefined,'recent-row');b.append(el('strong',task.title),el('span',task.updated?fmt.format(task.updated):'Дата неизвестна'));b.onclick=()=>{setTab('chats');openTask(task);};$('latest').append(b);}
  if(!tasks.length)$('latest').append(el('p',pendingList?'Читаем список…':'В этой выборке пока нет чатов.','empty'));
  renderList();updateButtons();
}
function renderList(){
  const filter=$('filter').value.trim().toLocaleLowerCase('ru');
  const shown=tasks.filter(t=>!filter||t.title.toLocaleLowerCase('ru').includes(filter));
  $('task-list').replaceChildren();$('list-count').textContent='Загружено '+tasks.length+(filter?' · показано '+shown.length:'')+(pageCursor?' · есть ещё':'');
  for(const task of shown){const b=el('button',undefined,'task-row'+(selected?.id===task.id?' selected':''));
    b.setAttribute('aria-pressed',String(selected?.id===task.id));b.title=task.fullTitle||task.title;b.append(el('strong',task.title),el('span',task.updated?'Изменено в источнике: '+fmt.format(task.updated):'Время изменения неизвестно','muted'));b.onclick=()=>openTask(task);$('task-list').append(b);}
  if(!shown.length)$('task-list').append(el('p',pendingList?'Загрузка…':filter?'В загруженной части совпадений нет. Поиск в источнике доступен ниже.':'Источник вернул пустой список.','empty'));
}
function clearDetail(){
  ++detailGeneration;selected=null;detail=null;pendingRead=false;$('detail-title').textContent='Выберите чат';$('turn-status').textContent='';$('context-scope').textContent='';
  $('thread-meta').textContent='Последний ход, ответы и ссылки появятся здесь.';$('answer').replaceChildren();
  $('materials').replaceChildren();$('identity').textContent='';$('detail-actions').hidden=true;$('read-more').hidden=true;save();
}
async function loadHost(id,more=false){
  if(pendingList)return;const generation=++listGeneration;pendingList=true;notice();
  if(!more){hostId=id;tasks=[];pageCursor=null;lastRead=null;hasRead=false;clearDetail();save();}
  draw();
  try{
    const h=currentHost();if(!h||h.route==='disabled'||h.availability==='disabled')throw new Error('Для этого источника подключение выключено.');
    const args={host_id:id,limit:5};if(more)args.cursor=pageCursor;const search=$('remote-search').value.trim();if(search)args.search=search;
    const data=await call(callName('list_tasks'),args);if(generation!==listGeneration)return;
    const page=normalizePage(data,id);tasks=mergePage(tasks,page.tasks);
    if(more&&page.cursor===pageCursor){pageCursor=null;throw new Error('Источник повторил курсор. Уже прочитанные чаты сохранены; повтор остановлен.');}
    pageCursor=page.cursor;hasRead=true;lastRead=snapshot?snapshotAt:new Date();
  }catch(e){if(generation===listGeneration)notice(e.message,true);}
  finally{if(generation===listGeneration){pendingList=false;draw();}}
}
function drawDetail(){
  const sourceTitle=selected.fullTitle||selected.title;
  $('detail-title').textContent=sourceTitle;
  const states={completed:'Ход завершён',inProgress:'Ход выполняется',failed:'Ход с ошибкой',interrupted:'Ход прерван'};
  $('turn-status').textContent='Статус выбранного хода: '+(states[detail.latest]||'неизвестен');
  $('thread-meta').textContent=(snapshot?'Снимок · ':'')+readStamp(detail.readAt)+' · '+(selected.updated?'Изменено в источнике: '+fmt.format(selected.updated):'Время изменения неизвестно')+(detail.loadState==='not_loaded'?' · Чат не загружен в приложении':'');
  $('answer').replaceChildren(el('pre',detail.text||'Источник вернул пустой текст. Это не подтверждение отсутствия истории.','answer-text'));
  $('materials').replaceChildren();const links=safeLinks(detail.text);
  for(const link of links){const b=el('button',undefined,'material');b.append(el('strong',link.label),el('small',link.host));b.onclick=async()=>{try{if(preview)window.open(link.url,'_blank','noopener,noreferrer');else await app.openLink({url:link.url});}catch{notice('Этот host не открыл ссылку. Она остаётся в тексте результата.',true);}};$('materials').append(b);}
  if(!links.length)$('materials').append(el('p','В этой части ответа нет доступных веб-ссылок. Пути к локальным материалам сохраняются в тексте.','muted'));
  const context=contextSelection(detail,hostId,selected.id);
  const letters=Array.from(sourceTitle),scopeTitle=letters.length>80?letters.slice(0,79).join('')+'…':sourceTitle;
  $('context-scope').title=sourceTitle;
  $('context-scope').textContent=(currentHost()?.label||hostId)+' → '+scopeTitle+' · '+(detail.pages.length===1?'выбранный ход':'загружено страниц: '+detail.pages.length)+(context.structuredContent.truncated?' · обрезано до 12 000 символов':'');
  $('identity').textContent=JSON.stringify(context.structuredContent,null,2)+'\nЗавершение хода не означает завершение всей задачи. Проценты в названии — текст источника.';
  $('detail-actions').hidden=false;$('read-more').hidden=!detail.cursor;updateButtons();
}
async function openTask(task,more=false){
  const generation=++detailGeneration;selected=task;detail=more?detail:null;pendingRead=true;save();renderList();updateButtons();
  if(!more){$('detail-title').textContent=task.fullTitle||task.title;$('turn-status').textContent='Читаем выбранный ход…';$('thread-meta').textContent='';$('context-scope').textContent='';$('answer').replaceChildren();$('materials').replaceChildren();$('identity').textContent='';$('detail-actions').hidden=true;$('read-more').hidden=true;}
  const selectedHost=hostId;
  try{
    const args={host_id:selectedHost,thread_id:task.id,turn_limit:1};if(currentHost()?.route!=='desktop_cloud')args.wait_seconds=0;if(more)args.cursor=detail.cursor;
    const data=await call(callName('read_task'),args);if(generation!==detailGeneration||hostId!==selectedHost)return;
    const next=readIdentity(data,selectedHost,task.id);
    if(more&&next.cursor&&next.cursor===detail.cursor)throw new Error('Источник повторил курсор ответа. Повтор остановлен.');
    detail=more?mergeReadPages(detail,next):next;detail.readAt=snapshot?snapshotAt:new Date();drawDetail();notice();
  }catch(e){if(generation===detailGeneration){notice(e.message,true);if(!detail)$('turn-status').textContent='Статус выбранного хода: неизвестен';$('thread-meta').textContent='Прочитать выбранный чат не удалось. Другой источник не подставлялся.';}}
  finally{if(generation===detailGeneration){pendingRead=false;updateButtons();}}
}
async function initialize(data={}){
  // The host may deliver its tool result after the initialize handshake.
  // Preserve provenance even when inventory fallback already started.
  if(data.preview_snapshot){
    snapshot=true;
    if(data.snapshot_at){const date=new Date(data.snapshot_at);if(Number.isFinite(date.getTime()))snapshotAt=date;}
    if(hasRead)lastRead=snapshotAt;
  }
  $('mode').textContent=snapshot?'Предпросмотр · снимок':'Рабочая панель';$('snapshot-note').hidden=!snapshot;
  if(started){draw();return;}started=true;
  try{
    const source=Array.isArray(data.hosts)?data:await call('codex_list_hosts',{});
    hosts=(source.hosts||[]).filter(h=>h&&typeof h.host_id==='string');$('host').replaceChildren();
    for(const h of hosts){const o=el('option',cleanText(h.label||h.host_id));o.value=h.host_id;o.disabled=h.route==='disabled'||h.availability==='disabled';$('host').append(o);}
    const enabled=hosts.filter(h=>h.route!=='disabled'&&h.availability!=='disabled');
    hostId=enabled.some(h=>h.host_id===selection.host_id)?selection.host_id:enabled.find(h=>h.host_id==='owner-host')?.host_id||enabled[0]?.host_id||'';
    $('host').value=hostId;if(hostId)await loadHost(hostId);else{draw();notice('Нет подключённых источников. Пустой список не заменяется тестовыми задачами.',true);}
  }catch(e){started=false;notice(e.message,true);}
}
$('host').onchange=()=>loadHost($('host').value);
$('refresh').onclick=()=>loadHost(hostId);$('more').onclick=()=>loadHost(hostId,true);
$('filter').oninput=renderList;
$('search-form').onsubmit=e=>{e.preventDefault();loadHost(hostId);};
$('reread').onclick=()=>openTask(selected);$('read-more').onclick=()=>openTask(selected,true);
for(const b of document.querySelectorAll('[data-tab]'))b.onclick=()=>setTab(b.dataset.tab);
$('show-chats').onclick=()=>setTab('chats');
$('attach').onclick=async()=>{
  if(!modelContext||!detail||pendingRead)return;
  try{await modelContext.update(contextSelection(detail,hostId,selected.id));notice('Контекст выбранного чата добавлен. Сообщение не отправлено.');}catch{notice('Host не принял контекст. Выбранный чат сохранён.',true);}
};
$('copy-identity').onclick=async()=>{if(!detail)return;try{await navigator.clipboard.writeText(JSON.stringify(contextSelection(detail,hostId,selected.id).structuredContent,null,2));notice('Идентификаторы скопированы.');}catch{notice('Не удалось скопировать. Идентификаторы доступны в деталях.',true);}};
async function start(){
  if(preview){$('preview-login').hidden=false;document.querySelector('header').hidden=true;document.querySelector('main').hidden=true;return;}
  app=new App({name:'integrity-workbench',version:'0.2.0'});extensions=new OpenAIExtensions(app);
  function theme(){const ctx=app.getHostContext();if(ctx?.theme)applyDocumentTheme(ctx.theme);if(ctx?.styles?.variables)applyHostStyleVariables(ctx.styles.variables);}
  let ready=false,initial;
  app.ontoolresult=result=>{if(!ready)initial=result.structuredContent;else initialize(result.structuredContent).catch(e=>notice(e.message,true));};
  app.addEventListener('hostcontextchanged',theme);await app.connect();modelContext=extensions.modelContext;theme();ready=true;
  await initialize(initial||{});
}
$('preview-login-form').onsubmit=async event=>{
  event.preventDefault();const token=$('preview-token').value;$('preview-token').value='';
  try{const data=unpack(await previewClient.connect(token));if(data.mode!=='workspace')throw new Error('Этот интерфейс требует явно настроенный Hub.');
    $('preview-login').hidden=true;document.querySelector('header').hidden=false;document.querySelector('main').hidden=false;await initialize(data);
  }catch(error){notice(error.message,true);}
};
setTab('overview');start().catch(e=>notice(e.message,true));

