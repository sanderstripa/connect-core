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
    await page.locator('#settings').click();assert.match(await page.locator('#dialog-body').innerText(),/безопасное автообновление/);await page.locator('#close-dialog').click();
    await page.locator('#devices button').click();await page.getByRole('button',{name:'Отозвать сертификат',exact:true}).click();await page.getByRole('button',{name:'Подтвердить',exact:true}).click();await page.locator('#dialog').waitFor({state:'hidden'});await page.getByRole('cell',{name:'Отозван',exact:true}).waitFor();
    await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(artifacts,'connect-ui-mobile.png'),fullPage:true});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'mobile page overflow');
    await stop(controller);await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('server-status').textContent==='Неизвестно');assert.equal(await page.locator('#start').isDisabled(),true);
    await page.locator('#logout').click();await page.locator('#login').waitFor({state:'visible'});
    assert.equal(errors.length,0,errors.join('\n'));
    await fs.writeFile(path.join(artifacts,'result.json'),JSON.stringify({passed:true,real_control:true,real_data_server:'stopped (TUN not started)',checks:['unauthenticated API','login CSRF','login/session','real status/metrics','rename persistence','themes','logs','settings capabilities','revocation confirmation','mobile layout','offline core unknown state','logout'],browser_errors:errors},null,2));
    console.log('Browser checks passed; screenshots show actual stopped lab core and live host metrics.');
  } finally {if(browser)await browser.close();for(const p of children)await stop(p);await fs.rm(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
