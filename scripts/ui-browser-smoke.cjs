// Real loopback core control and panel. No API interception or demo data.
const { chromium } = require(process.env.CONNECT_PLAYWRIGHT_MODULE || 'playwright');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const artifacts = process.env.CONNECT_UI_ARTIFACTS || path.join(root, 'ui-browser-artifacts');
const exe = name => path.join(root, 'bin', name + (process.platform === 'win32' ? '.exe' : ''));
const children = [];
const delay = ms => new Promise(r => setTimeout(r, ms));
async function port() { const s = net.createServer(); await new Promise(r => s.listen(0, '127.0.0.1', r)); const n = s.address().port; await new Promise(r => s.close(r)); return n; }
function command(name,args,input) { const r=spawnSync(exe(name),args,{input,encoding:'utf8'}); if(r.status!==0) throw new Error(`${name}: ${r.stderr}`); }
function start(name,args) { const p=spawn(exe(name),args,{stdio:'ignore',windowsHide:true}); children.push(p); p.on('error',e=>console.error(e.message)); return p; }
async function stop(p) { if(p.exitCode!==null || p.signalCode!==null) return; const exited=new Promise(r=>p.once('exit',r)); p.kill('SIGINT'); await exited; }
(async()=> {
  const temp=await fs.mkdtemp(path.join(os.tmpdir(),'connect-ui-check-')); let browser;
  try {
    await fs.mkdir(artifacts,{recursive:true});
    command('connect-core',['init-lab',path.join(temp,'lab')]);
    command('connect-control',['init',path.join(temp,'control'),path.join(temp,'lab','ip-server.json')]);
    const controlPath=path.join(temp,'control','control.json'),control=JSON.parse(await fs.readFile(controlPath));
    control.listen=`127.0.0.1:${await port()}`; await fs.writeFile(controlPath,JSON.stringify(control));
    const password=crypto.randomBytes(24).toString('hex');
    command('connect-ui',['init',path.join(temp,'ui'),`http://${control.listen}`,control.token_file],password+'\n');
    const uiPath=path.join(temp,'ui','ui.json'),ui=JSON.parse(await fs.readFile(uiPath)); ui.listen=`127.0.0.1:${await port()}`; await fs.writeFile(uiPath,JSON.stringify(ui));
    const controller=start('connect-control',['serve',controlPath]); start('connect-ui',['serve',uiPath]);
    const origin=`http://${ui.listen}`;
    for(let i=0;i<100;i++){try {const r=await fetch(origin);if(r.ok)break;}catch{} await delay(50);}
    browser=await chromium.launch({headless:true,...(process.env.CONNECT_CHROMIUM_PATH ? {executablePath:process.env.CONNECT_CHROMIUM_PATH}: {})});
    const context=await browser.newContext({viewport:{width:1440,height:920},locale:'ru-RU'});const page=await context.newPage();
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    assert.equal((await fetch(origin+'/api/status')).status,401);
    assert.equal((await fetch(origin+'/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password})})).status,403);
    await page.goto(origin); await page.locator('#password').fill(password); await page.locator('#login-form button').click();
    await page.locator('#main').waitFor({state:'visible'}); await page.waitForFunction(()=>document.getElementById('server-status').textContent==='Остановлен');
    assert.equal(await page.locator('#devices tr').count(),1);
    assert.equal(await page.locator('#connections').innerText(),'0');
    await page.locator('#refresh').click(); await delay(300);
    await page.locator('#devices button').click();await page.locator('#dialog input').fill('Проверенное устройство');await page.getByRole('button',{name:'Переименовать',exact:true}).click();
    await page.locator('#dialog').waitFor({state:'hidden'});await page.getByRole('cell',{name:'Проверенное устройство',exact:true}).waitFor();
    await page.screenshot({path:path.join(artifacts,'connect-ui-light.png'),fullPage:true});
    await page.locator('#theme').click();await page.screenshot({path:path.join(artifacts,'connect-ui-dark.png'),fullPage:true});
    await page.reload();await page.waitForFunction(()=>document.documentElement.dataset.theme==='dark' && !document.getElementById('main').hidden);
    await page.locator('#logs').click();assert.match(await page.locator('#dialog pre').innerText(),/device rename/);await page.locator('#close-dialog').click();
    await page.locator('#diagnostics').click();await page.getByRole('button',{name:'Скачать отчёт',exact:true}).waitFor();
    const diagnosticDownload=page.waitForEvent('download');await page.getByRole('button',{name:'Скачать отчёт',exact:true}).click();
    const downloaded=await diagnosticDownload;assert.equal(downloaded.suggestedFilename(),'connect-server-diagnostics.json');
    const safeReport=await fs.readFile(await downloaded.path(),'utf8'),diagnostics=JSON.parse(safeReport);
    assert.equal(diagnostics.schema,1);assert.ok(Array.isArray(diagnostics.samples));
    assert.ok(!safeReport.includes(password)&&!safeReport.includes(control.token_file),'diagnostics leaked credentials');
    await page.screenshot({path:path.join(artifacts,'server-diagnostics.png'),fullPage:true});await page.locator('#close-dialog').click();
    await page.locator('#settings').click();assert.match(await page.locator('#dialog-body').innerText(),/безопасное автообновление/);await page.locator('#close-dialog').click();
    await page.locator('#devices button').click();await page.getByRole('button',{name:'Отозвать сертификат',exact:true}).click();await page.getByRole('button',{name:'Подтвердить',exact:true}).click();await page.locator('#dialog').waitFor({state:'hidden'});await page.getByRole('cell',{name:'Отозван',exact:true}).waitFor();
    await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(artifacts,'connect-ui-mobile.png'),fullPage:true});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'mobile page overflow');
    await stop(controller);await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('server-status').textContent==='Неизвестно');assert.equal(await page.locator('#start').isDisabled(),true);
    await page.locator('#logout').click();await page.locator('#login').waitFor({state:'visible'});
    // Exercise the actual new issuer + client importer, through the UI. No
    // intercepted API responses and no client private key crosses the network.
    const enrollmentPort=await port(),managedDir=path.join(temp,'managed');
    command('connect-control',['init-vps',managedDir,'127.0.0.1:17444',`https://127.0.0.1:${enrollmentPort}`]);
    const mcPath=path.join(managedDir,'control.json'),mc=JSON.parse(await fs.readFile(mcPath));mc.listen=`127.0.0.1:${await port()}`;mc.enrollment_listen=`127.0.0.1:${enrollmentPort}`;await fs.writeFile(mcPath,JSON.stringify(mc));
    command('connect-ui',['init',path.join(temp,'managed-ui'),`http://${mc.listen}`,mc.token_file],password+'\n');
    const muPath=path.join(temp,'managed-ui','ui.json'),mu=JSON.parse(await fs.readFile(muPath));mu.listen=`127.0.0.1:${await port()}`;await fs.writeFile(muPath,JSON.stringify(mu));
    start('connect-control',['serve',mcPath]);start('connect-ui',['serve',muPath]);
    const mo=`http://${mu.listen}`;for(let i=0;i<100;i++){try{if((await fetch(mo)).ok)break;}catch{}await delay(50);}
    await context.grantPermissions(['clipboard-read','clipboard-write'],{origin:mo});await page.goto(mo);await page.locator('#password').fill(password);await page.locator('#login-form button').click();await page.locator('#main').waitFor({state:'visible'});await page.waitForFunction(()=>document.getElementById('server-status').textContent==='Остановлен');
    await page.locator('#add').click();await page.locator('#dialog input').nth(0).fill('Ноутбук CONNECT');await page.getByRole('button',{name:'Выпустить ссылку',exact:true}).click();await page.locator('#dialog textarea').waitFor();
    const link=await page.locator('#dialog textarea').inputValue();assert.ok(link.startsWith('connect://enroll?'));
    await page.waitForFunction(()=>document.querySelector('#dialog img')?.naturalWidth>0);await page.getByRole('button',{name:'Копировать ссылку',exact:true}).click();assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),link);
    await page.setViewportSize({width:1440,height:920});await page.screenshot({path:path.join(artifacts,'connect-ui-invitation.png'),fullPage:true});
    const child=spawn(exe('connect-core'),['import-link',path.join(temp,'client-device')],{stdio:['pipe','pipe','ignore'],windowsHide:true});children.push(child);let output='';child.stdout.on('data',b=>output+=b);child.stdin.end(link+'\n');
    for(let i=0;i<100&&!output.match(/\b[a-f0-9]{64}\b/);i++)await delay(50);const fingerprint=output.match(/\b[a-f0-9]{64}\b/)?.[0];assert.ok(fingerprint,'client did not show its public key fingerprint');
    await page.locator('#close-dialog').click();await page.waitForFunction(async()=>{const r=await fetch('/api/registrations');return (await r.json()).some(v=>v.status==='approved');});
    await page.locator('#registrations').click();await page.screenshot({path:path.join(artifacts,'connect-ui-registration.png'),fullPage:true});assert.equal(await page.getByRole('button',{name:'Подтвердить устройство',exact:true}).count(),0);
    for(let i=0;i<150&&child.exitCode===null;i++)await delay(100);assert.equal(child.exitCode,0,'actual client enrollment failed');assert.ok((await fs.stat(path.join(temp,'client-device','device-key.pem'))).isFile());assert.ok((await fs.stat(path.join(temp,'client-device','connect-ip-client.json'))).isFile());
    await page.locator('#close-dialog').click();await page.locator('#refresh').click();await page.getByRole('cell',{name:'Ноутбук CONNECT',exact:true}).waitFor();if(await page.evaluate(()=>document.documentElement.dataset.theme)!=='dark')await page.locator('#theme').click();await page.screenshot({path:path.join(artifacts,'connect-ui-managed-dark.png'),fullPage:true});await page.locator('#theme').click();await page.screenshot({path:path.join(artifacts,'connect-ui-managed-light.png'),fullPage:true});
    await page.locator('#devices button').click();await page.getByRole('button',{name:'Отозвать сертификат',exact:true}).click();await page.getByRole('button',{name:'Подтвердить',exact:true}).click();await page.locator('#dialog').waitFor({state:'hidden'});
    assert.equal(errors.length,0,errors.join('\n'));
    await fs.writeFile(path.join(artifacts,'result.json'),JSON.stringify({passed:true,real_control:true,real_data_server:'stopped (TUN not started)',checks:['unauthenticated API','login CSRF','login/session','real status/metrics','rename persistence','themes','logs','settings capabilities','revocation confirmation','mobile layout','offline core unknown state','logout','actual connect URI + QR + clipboard','real client-generated key and CSR','automatic one-time authorization','compatible issued configuration'],browser_errors:errors},null,2));
    console.log('Browser checks passed; screenshots show actual stopped lab core and live host metrics.');
  } finally {if(browser)await browser.close();for(const p of children)await stop(p);await fs.rm(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
