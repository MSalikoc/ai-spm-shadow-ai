// Dependency-free Chrome/CDP interaction checks. All HTTP traffic is intercepted.
// Run: node tests\browser_workflow.mjs [--screenshots]
import assert from 'node:assert/strict';
import {spawn, execFileSync} from 'node:child_process';
import {readFile, writeFile, mkdir, rm} from 'node:fs/promises';
import path from 'node:path';
import {once} from 'node:events';
import {pathToFileURL} from 'node:url';

const root = process.cwd();
const profile = path.join(root, '.browser-workflow-profile');
const chromePath = process.env.CHROME || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const sample = await readFile(path.join(root, 'docs', 'sample-assessment.html'), 'utf8');
const empty = execFileSync('python', ['-X','utf8','-c',
  'import assessment_report; print(assessment_report.html_string([], [], "Browser fixture"))'],
  {encoding:'utf8'});
const seed = JSON.parse(sample.split('id="workflow-seed">')[1].split('</script>')[0]);
let stored = structuredClone(seed.states), getError = false, postError = 0, postDelay = 0, getDelay = 0;
let posts = [], reads = 0, serial = 0, assertions = 0;
const errors = [], network = [];
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
await mkdir(profile); // Refuse to reuse or remove somebody else's Chrome profile.
const chrome = spawn(chromePath, [
  '--headless=new', '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
  '--disable-component-update', '--disable-sync', '--remote-debugging-port=0',
  '--user-data-dir='+profile, 'about:blank'
], {stdio:'ignore'});
let socket;
try {
  let port;
  for (let i=0;i<100;i++) {
    try { port = (await readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0]; break; }
    catch { await pause(100); }
  }
  assert.ok(port,'Chrome starts with a debugging port');
  const tabs = await (await fetch('http://127.0.0.1:'+port+'/json/list')).json();
  socket = new WebSocket(tabs.find(tab => tab.type === 'page').webSocketDebuggerUrl);
  await once(socket,'open');
  let id = 0;
  const pending = new Map(), events = new Map();
  function call(method, params = {}) {
    const messageId = ++id;
    return new Promise((resolve,reject) => {
      pending.set(messageId,{resolve,reject});
      socket.send(JSON.stringify({id:messageId,method,params}));
    });
  }
  function nextEvent(name) { return new Promise(resolve => events.set(name,resolve)); }
  async function fulfill(requestId,status,body,type='application/json') {
    await call('Fetch.fulfillRequest',{requestId,responseCode:status,
      responseHeaders:[{name:'Content-Type',value:type},{name:'Cache-Control',value:'no-store'}],
      body:Buffer.from(body).toString('base64')});
  }
  async function intercept(event) {
    const {request,requestId} = event, url = new URL(request.url);
    network.push({url:request.url,method:request.method,headers:request.headers});
    if (url.protocol === 'file:' && url.pathname ===
        pathToFileURL(path.join(root,'docs','sample-assessment.html')).pathname) {
      await call('Fetch.continueRequest',{requestId}); return;
    }
    if (url.pathname === '/api/assessment' || url.pathname === '/sample-assessment.html') {
      let html = url.searchParams.has('empty') ? empty : sample;
      if (url.pathname === '/api/assessment') html = html.replace(
        'name="decision-context" content="snapshot"', 'name="decision-context" content="live"');
      await fulfill(requestId,200,html,'text/html'); return;
    }
    if (url.hostname === 'dashboard.test' && url.pathname === '/api/decisions') {
      assert.equal(Object.entries(request.headers).find(([key]) =>
        key.toLowerCase() === 'x-functions-key')?.[1],'fixture-key');
      assert.equal(url.search,'','API key is not sent in query');
      if (request.method === 'GET') {
        reads++;
        if (getDelay) await pause(getDelay);
        await fulfill(requestId,getError ? 503 : 200,JSON.stringify(getError ?
          {store_status:'corrupt',error:'Workflow store is corrupt'} :
          {store_status:'ok',as_of:'2026-09-05T12:00:00Z',decisions:stored}));
      } else {
        const body = JSON.parse(request.postData); posts.push(body);
        if (postDelay) await pause(postDelay);
        const conflict = body.expected_revision !== stored[body.decision_key].revision;
        const error = postError || (conflict ? 409 : 0);
        if (error) await fulfill(requestId,error,JSON.stringify({error:
          error === 409 ? 'Decision changed concurrently' : 'Server validation rejected the record'}));
        else {
          const record = stored[body.decision_key], before = record.owner;
          Object.assign(record,body,{persisted:true,revision:'fixture-revision-'+(++serial),
            updated_at:'2026-09-05T12:00:00Z',overdue:false});
          record.history.push({timestamp:record.updated_at,field:'owner',from:before,to:record.owner});
          delete record.expected_revision;
          await fulfill(requestId,200,JSON.stringify({decision:record}));
        }
      }
      return;
    }
    await call('Fetch.failRequest',{requestId,errorReason:'BlockedByClient'});
  }
  socket.addEventListener('message',event => {
    const data = JSON.parse(event.data);
    if (data.id) {
      const item = pending.get(data.id); pending.delete(data.id);
      data.error ? item.reject(new Error(JSON.stringify(data.error))) : item.resolve(data.result);
    } else {
      if (data.method === 'Runtime.exceptionThrown') errors.push(data.params.exceptionDetails);
      if (events.has(data.method)) { events.get(data.method)(data.params); events.delete(data.method); }
      if (data.method === 'Fetch.requestPaused') intercept(data.params).catch(error => errors.push(String(error)));
    }
  });
  async function evaluate(expression) {
    const result = await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  async function check(expression,label) {
    if (!await evaluate(expression)) {
      console.error(label, errors, await evaluate(`({width:innerWidth,scroll:document.documentElement.scrollWidth,
        view:document.querySelector('.view.on')?.id,count:document.getElementById('count')?.textContent,
        controlIds:[...document.querySelectorAll('#tbody tr')].filter(r=>r.style.display!=='none').map(r=>r.id),
        overflow:[...document.querySelectorAll('body *')].filter(e=>{
          const r=e.getBoundingClientRect();return r.width && (r.right>innerWidth+1 || r.left< -1);
        }).slice(0,12).map(e=>({tag:e.tagName,id:e.id,cls:e.className,right:e.getBoundingClientRect().right}))})`));
      assert.fail(label);
    }
    assertions++;
  }
  async function wait(expression) {
    for (let i=0;i<200;i++) { if (await evaluate(expression)) return; await pause(30); }
    throw new Error('Timed out: '+expression);
  }
  async function navigate(url) {
    const loaded = nextEvent('Page.loadEventFired');
    await call('Page.navigate',{url}); await loaded;
  }
  async function click(selector) { await evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`); }
  async function fill(id,value) {
    await evaluate(`(()=>{const el=document.getElementById(${JSON.stringify(id)});
      el.value=${JSON.stringify(value)};el.dispatchEvent(new Event('input',{bubbles:true}));
      el.dispatchEvent(new Event('change',{bubbles:true}));})()`);
  }
  async function key(key,shift=false) {
    const code = {Tab:9,Escape:27,Enter:13}[key];
    await call('Input.dispatchKeyEvent',{type:'keyDown',key,code:key,windowsVirtualKeyCode:code,modifiers:shift ? 8 : 0});
    await call('Input.dispatchKeyEvent',{type:'keyUp',key,code:key,windowsVirtualKeyCode:code,modifiers:shift ? 8 : 0});
    if (key === 'Escape') await wait(`!document.getElementById('workflow-dialog').open &&
      !document.getElementById('workflow-dialog').contains(document.activeElement)`);
  }
  async function screenshot(file) {
    const shot = await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
    await writeFile(path.join(root,file),Buffer.from(shot.data,'base64'));
  }
  await call('Page.enable'); await call('Runtime.enable');
  await call('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]});
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:1120,deviceScaleFactor:1,mobile:false});
  await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'dark'}]});
  await navigate('https://static.test/sample-assessment.html?scoutTheme=light');
  await check(`document.documentElement.dataset.theme==='light'`,'explicit light beats dark preference');
  await check(`document.getElementById('workflow-mode').textContent.includes('Read-only snapshot')`,'static is read-only');
  await check(`document.documentElement.scrollWidth<=innerWidth`,'desktop has no horizontal overflow');
  await check(`(() => {
    const charts=[...document.querySelectorAll('.dashboard-charts svg')];
    return charts.length===3 && charts.every(chart=>{
      const box=chart.getBoundingClientRect();
      return !chart.closest('details') && box.height>0 && box.top>=0 && box.bottom<900;
    });
  })()`,'three real dashboard charts are visible before scrolling on desktop');
  await check(`document.querySelector('.dashboard-context').textContent.includes('DEMO / SYNTHETIC DATA') &&
    [...document.querySelectorAll('.dashboard-kpi strong')].map(n=>n.textContent).join(',')==='28,24,13,7'`,
    'demo is labelled and headline values agree with the synthetic scan');
  await check(`(() => {
    const canvas=document.createElement('canvas'),ctx=canvas.getContext('2d');
    function luminance(color) {
      ctx.fillStyle=color;ctx.fillRect(0,0,1,1);
      const rgb=[...ctx.getImageData(0,0,1,1).data].slice(0,3).map(v=>{
        v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;
      });
      return rgb[0]*.2126+rgb[1]*.7152+rgb[2]*.0722;
    }
    const surface=getComputedStyle(document.querySelector('.card')).backgroundColor;
    const probe=document.createElement('span');document.body.append(probe);
    const colors=['--cp-success-readable','--cp-warning-readable'].map(token=>{
      probe.style.color='var('+token+')';return getComputedStyle(probe).color;
    });probe.remove();
    const bg=luminance(surface);
    return colors.every(color=>{
      const fg=luminance(color);return (Math.max(fg,bg)+.05)/(Math.min(fg,bg)+.05)>=4.5;
    });
  })()`,'light status foregrounds meet AA contrast on cards and passed badges');
  assert.equal(reads,0);
  if (process.argv.includes('--screenshots')) {
    await screenshot(path.join('docs','img','assessment.png'));
    await click('nav [data-view="assessment"]');
    await click('#control-AISPM-1001');
    await wait(`document.getElementById('panel').getAttribute('aria-hidden')==='false'`);
    await pause(300);
    await screenshot(path.join('docs','img','assessment-detail.png'));
    await click('#pclose');
    await click('nav [data-view="overview"]');
    await evaluate('window.scrollTo(0,0)');
  }
  await click('[data-edit-decision="sensitive-access"]');
  await check(`document.getElementById('workflow-dialog').open &&
    document.getElementById('workflow-fields').disabled &&
    document.getElementById('workflow-save').disabled`,'static editor cannot save');
  await key('Escape');
  await check(`!document.getElementById('workflow-dialog').open &&
    document.activeElement.dataset.editDecision==='sensitive-access'`,'Escape returns focus');
  await click('#theme');
  await check(`document.documentElement.dataset.theme==='dark'`,'toggle switches theme');
  await check(`getComputedStyle(document.body).backgroundColor==='rgb(61, 59, 58)'`,'dark legacy aliases use Clawpilot background');
  await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  await evaluate('window.scrollTo(0,0)');
  await check(`document.documentElement.scrollWidth<=innerWidth`,'mobile no horizontal overflow');
  if (process.argv.includes('--screenshots')) await screenshot('.browser-mobile.png');
  await click('[data-edit-decision="sensitive-access"]');
  await check(`document.getElementById('workflow-dialog').getBoundingClientRect().right<=innerWidth`,'mobile dialog fits');
  if (process.argv.includes('--screenshots')) await screenshot('.browser-mobile-editor.png');
  await key('Escape');
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:1120,deviceScaleFactor:1,mobile:false});

  stored['sensitive-access'].owner = 'Live IAM';
  await navigate('https://dashboard.test/api/assessment?code=fixture-key&scoutTheme=light');
  await wait(`document.getElementById('workflow-mode').textContent.startsWith('Current workflow loaded')`);
  await check(`!location.search.includes('code=') &&
    ![...document.querySelectorAll('a')].some(a=>a.href.includes('fixture-key'))`,'key removed and not copied to links');
  await check(`document.querySelector('[data-workflow="sensitive-access"]').textContent.includes('Live IAM')`,'GET overlays scan workflow');
  await click('[data-edit-decision="sensitive-access"]');
  await check(`!document.getElementById('workflow-fields').disabled`,'live current state enables form');
  if (process.argv.includes('--screenshots')) await screenshot('.browser-live-editor.png');
  getDelay = 250;
  await click('#workflow-reload');
  await check(`document.getElementById('workflow-fields').disabled &&
    document.getElementById('workflow-save').disabled`,
    'editing and save cannot race a pending reload');
  assert.equal(posts.length,0);
  await wait(`document.getElementById('workflow-form-message').textContent.startsWith('Editing current workflow')`);
  await click('#workflow-reload');
  await click('#workflow-close');
  await click('[data-edit-decision="governance"]');
  await fill('decision-notes','Draft must survive another editor reload');
  await pause(350);
  await check(`document.getElementById('decision-notes').value==='Draft must survive another editor reload'`,
    'delayed reload does not overwrite a different editor draft');
  await key('Escape');
  await click('[data-edit-decision="sensitive-access"]');
  getDelay = 0;
  await evaluate(`document.getElementById('workflow-close').focus()`);
  await key('Tab');
  await check(`document.getElementById('workflow-dialog').contains(document.activeElement)`,'forward Tab contained');
  await evaluate(`document.getElementById('decision-owner').focus()`);
  await key('Tab',true);
  await check(`document.getElementById('workflow-dialog').contains(document.activeElement)`,'reverse Tab contained');
  await fill('decision-status','Risk accepted');
  await check(`!document.getElementById('decision-acceptance').hidden &&
    document.getElementById('decision-rationale').required &&
    document.getElementById('decision-approver').required &&
    document.getElementById('decision-expiry').required &&
    !document.getElementById('workflow-form').checkValidity()`,'acceptance requires rationale approver and expiry');
  await fill('decision-status','Compensating control');
  await check(`document.getElementById('decision-acceptance').hidden &&
    !document.getElementById('decision-compensation').hidden &&
    document.getElementById('decision-control').required`,'compensating control toggles required fields');
  await fill('decision-notes','Browser-reviewed evidence');
  await fill('decision-owner','<img src=x onerror=alert(1)>');
  await fill('decision-status','Verified');
  postDelay = 250;
  await click('#workflow-save');
  await check(`document.getElementById('workflow-save').disabled &&
    document.getElementById('workflow-form').getAttribute('aria-busy')==='true'`,'saving locks editor');
  await wait(`document.getElementById('workflow-form-message').textContent.startsWith('Saved durably')`);
  await check(`document.getElementById('workflow-history').textContent.includes('<img')`,'history displays saved values as text');
  assert.ok(posts.at(-1).expected_revision); assertions++;
  assert.equal(posts.at(-1).notes,'Browser-reviewed evidence');
  assert.equal(posts.at(-1).acceptance,null); assertions++;
  await key('Escape');
  await check(`document.querySelector('[data-workflow="sensitive-access"]').textContent.includes('Verification needs review') &&
    !document.querySelector('[data-workflow="sensitive-access"] img')`,'conflict visible, unsafe markup is text');
  await check(`document.getElementById('decision-attention').textContent.includes('1 evidence conflicts')`,'attention counts evidence conflict');
  await click('[data-evidence]');
  await check(`document.getElementById('v-assessment').classList.contains('on') &&
    document.querySelectorAll('#tbody tr').length===26 &&
    [...document.querySelectorAll('#tbody tr')].filter(r=>r.style.display!=='none').length===5`,'decision drills into relevant controls');
  await click('#all-controls');
  await check(`[...document.querySelectorAll('#tbody tr')].every(r=>r.style.display!=='none')`,'full catalogue retained');
  await click('nav [data-view="overview"]');
  await click('[data-edit-decision="sensitive-access"]');
  const oldRevision = stored['sensitive-access'].revision;
  stored['sensitive-access'].revision = 'other-editor';
  stored['sensitive-access'].owner = 'Other editor';
  await fill('decision-owner','Stale draft');
  await click('#workflow-save');
  await wait(`document.getElementById('workflow-form-message').textContent.startsWith('Conflict:')`);
  await check(`document.getElementById('workflow-save').disabled`,'stale editor cannot blindly retry');
  assert.equal(posts.at(-1).expected_revision,oldRevision);
  assert.equal(stored['sensitive-access'].owner,'Other editor'); assertions++;
  await click('#workflow-reload');
  await wait(`document.getElementById('decision-owner').value==='Other editor' &&
    !document.getElementById('workflow-save').disabled`);
  postError = 400;
  await click('#workflow-save');
  await wait(`document.getElementById('workflow-form-message').textContent.includes('validation rejected')`);
  await check(`!document.getElementById('workflow-save').disabled`,'validation error permits correction');
  postError = 0; getError = true;
  await click('#workflow-save');
  await wait(`document.getElementById('workflow-form-message').textContent.startsWith('Saved on server')`);
  await check(`document.getElementById('workflow-save').disabled &&
    document.getElementById('workflow-mode').textContent.includes('not current')`,'post-success refresh failure is not stale success');
  await key('Escape'); getError = false;
  await click('#workflow-refresh');
  await wait(`document.getElementById('workflow-mode').textContent.startsWith('Current workflow loaded')`);
  await call('Emulation.setEmulatedMedia',{media:'print'});
  await check(`getComputedStyle(document.getElementById('workflow-auth')).display==='none' &&
    getComputedStyle(document.getElementById('v-overview')).display==='block' &&
    getComputedStyle(document.querySelector('.dashboard-header')).display!=='none' &&
    document.querySelector('.dashboard-context').textContent.includes('2026-08-01')`,'print omits credentials and includes scan as of');
  await call('Emulation.setEmulatedMedia',{media:''});

  // A scan with no active cards must still reveal a subsequently recorded decision.
  await navigate('https://dashboard.test/api/assessment?empty=1&code=fixture-key');
  await wait(`document.getElementById('workflow-mode').textContent.startsWith('Current workflow loaded')`);
  await check(`!document.querySelector('article.decision') &&
    document.querySelector('[data-review-status="governance"]').textContent.includes('Requires review')`,'new persisted program remains discoverable on old scan');
  await click('[data-edit-decision="governance"]');
  await check(`document.getElementById('decision-status').value==='Risk accepted'`,'all-program editor has current omitted state');
  await key('Escape');
  getError = true;
  await click('#workflow-refresh');
  await wait(`document.getElementById('workflow-mode').textContent.includes('store is corrupt')`);
  await check(`document.getElementById('decision-attention').textContent.includes('unavailable')`,'GET failure has explicit unavailable attention');
  getError = false;
  await navigate('https://dashboard.test/api/assessment');
  await check(`document.getElementById('workflow-mode').textContent.includes('load current workflow')`,'keyless live page asks for credentials');
  await fill('workflow-key','fixture-key');
  await click('#workflow-connect');
  await wait(`document.getElementById('workflow-mode').textContent.startsWith('Current workflow loaded')`);
  await check(`document.getElementById('workflow-key').value===''`,'entered key cleared from form');
  const beforeFile = reads;
  await navigate(pathToFileURL(path.join(root,'docs','sample-assessment.html')).href+'?code=fixture-key');
  await check(`document.getElementById('workflow-auth').hidden &&
    document.getElementById('workflow-mode').textContent.includes('Read-only snapshot')`,'file artifact never enables API access');
  assert.equal(reads,beforeFile);
  await navigate('http://localhost/api/assessment?code=fixture-key');
  await check(`document.getElementById('workflow-auth').hidden`,'localhost cannot activate live mode');
  assert.equal(posts.length,4);
  assert.equal(errors.length,0,JSON.stringify(errors));
  assert.ok(network.filter(item => item.url.includes('/api/decisions')).every(item =>
    item.url==='https://dashboard.test/api/decisions'));
  console.log(`Browser checks passed: ${assertions}; desktop 1440x1120, mobile 390x844, light/dark, print, keyboard, GET/POST/409/400/503. ${reads} stub GETs, ${posts.length} stub POSTs; no tenant requests.`);
} finally {
  socket?.close();
  chrome.kill();
  await once(chrome,'exit').catch(()=>{});
  for (let i=0;i<30;i++) {
    try { await rm(profile,{recursive:true,force:true}); break; }
    catch (error) { if (i===29) throw error; await pause(100); }
  }
}
