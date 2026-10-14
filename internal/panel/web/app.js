'use strict';
const $ = id => document.getElementById(id);
let csrf = '', snapshot = null, pending = false;
const theme = localStorage.getItem('connect-theme') === 'dark' ? 'dark' : 'light';
function setTheme(t) { document.documentElement.dataset.theme = t; localStorage.setItem('connect-theme', t); $('theme').textContent = t === 'dark' ? 'Светлая тема' : 'Тёмная тема'; }
setTheme(theme);
function text(id, value) { $(id).textContent = value; }
function notice(message = '') { text('notice', message); $('notice').hidden = !message; }
function bytes(n) { if (n == null) return 'Недоступно'; const units = ['Б', 'КиБ', 'МиБ', 'ГиБ', 'ТиБ']; let i = 0; while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${units[i]}`; }
async function api(path, body) {
  const res = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Connect-UI': '1', 'X-CSRF-Token': csrf }, body: body === undefined ? undefined : JSON.stringify(body) });
  const result = await res.json();
  if (!res.ok) { if (res.status === 401 && path !== '/auth/login') signedOut(); throw new Error(result.error || `HTTP ${res.status}`); }
  return result;
}
function signedOut() { csrf = ''; snapshot = null; $('main').hidden = true; $('login').hidden = false; $('dialog').close(); }
function signedIn() { $('login').hidden = true; $('main').hidden = false; $('password').value = ''; }
async function refresh() {
  try { snapshot = await api('/api/status'); render(snapshot); notice(); }
  catch (e) { snapshot = null; text('server-status', 'Неизвестно'); $('server-status').className = 'badge error'; for (const id of ['core','protocol','endpoint','transport','uptime','connections','cpu','ram','disk','rx','tx','sessions']) text(id,'—'); $('devices').replaceChildren(); for (const id of ['start','stop','restart','add']) $(id).disabled = true; text('updated', 'Состояние не подтверждено'); notice(e.message); }
}
function render(s) {
  const names = { running: 'Работает', stopped: 'Остановлен', stopping: 'Останавливается', error: 'Ошибка' };
  text('server-status', names[s.status] || 'Неизвестно'); $('server-status').className = `badge ${s.status}`;
  text('core', s.core_version); text('protocol', `CONNECT IP v${s.protocol_version}`); text('endpoint', s.endpoint); text('transport', s.transport);
  const seconds = s.uptime_seconds; text('uptime', `${Math.floor(seconds / 3600)} ч ${Math.floor(seconds % 3600 / 60)} мин ${seconds % 60} с`); text('connections', s.active_sessions);
  $('start').disabled = s.status === 'running' || s.status === 'stopping'; $('stop').disabled = s.status !== 'running'; $('restart').disabled = s.status === 'stopping'; $('add').disabled = false;
  const m = s.metrics; text('cpu', m.cpu_percent == null ? 'Ожидание замера' : `${m.cpu_percent.toFixed(1)} %`); text('ram', `${bytes(m.ram_used_bytes)} / ${bytes(m.ram_total_bytes)}`); text('disk', `${bytes(m.disk_used_bytes)} / ${bytes(m.disk_total_bytes)}`); text('rx', bytes(s.received_bytes)); text('tx', bytes(s.sent_bytes)); text('sessions', s.active_sessions);
  text('updated', `Обновлено ${new Date().toLocaleTimeString('ru-RU')}`);
  $('devices').replaceChildren();
  for (const d of [...s.devices].sort((a,b) => a.name.localeCompare(b.name))) {
    const row = document.createElement('tr');
    const labels = { enabled: 'Разрешён', disabled: 'Отключён', revoked: 'Отозван' };
    for (const value of [d.name, labels[d.access] || d.access, d.connected ? 'Подключено' : 'Отключено', d.ip, bytes(d.received_bytes), bytes(d.sent_bytes), !d.last_activity || d.last_activity.startsWith('0001') ? '—' : new Date(d.last_activity).toLocaleString('ru-RU')]) { const td = document.createElement('td'); td.textContent = value; row.append(td); }
    const td = document.createElement('td'), button = document.createElement('button'); button.textContent = 'Управление'; button.onclick = () => showDevice(d); td.append(button); row.append(td); $('devices').append(row);
  }
  if (!s.devices.length) { const row = document.createElement('tr'), td = document.createElement('td'); td.colSpan = 8; td.className = 'empty'; td.textContent = 'Устройства не добавлены. Для доступа нужен сертификат доверенного CA.'; row.append(td); $('devices').append(row); }
}
function dialog(title) { text('dialog-title',title); $('dialog-body').replaceChildren(); if (!$('dialog').open) $('dialog').showModal(); return $('dialog-body'); }
function paragraph(parent, message, cls = '') { const p = document.createElement('p'); p.textContent = message; p.className = cls; parent.append(p); return p; }
function field(parent, title, value = '', multiline = false) { const label = document.createElement('label'); label.textContent = title; const input = document.createElement(multiline ? 'textarea' : 'input'); input.value = value; label.append(input); parent.append(label); return input; }
function action(parent, label, fn, primary = false) { const button = document.createElement('button'); button.textContent = label; if (primary) button.className = 'primary'; button.onclick = async () => { if (pending) return; pending = true; button.disabled = true; try { await fn(); } catch (e) { notice(e.message); } finally { pending = false; button.disabled = false; } }; parent.append(button); return button; }
function confirmAction(title, message, fn) { const body = dialog(title); paragraph(body, message); const buttons = document.createElement('div'); buttons.className = 'dialog-actions'; body.append(buttons); action(buttons,'Отмена',async()=> $('dialog').close()); action(buttons,'Подтвердить',async()=> { await fn(); $('dialog').close(); await refresh(); },true); }
async function download(path, name) { const res = await fetch(path, {credentials:'same-origin'}); if (!res.ok) { const e = await res.json(); throw new Error(e.error); } const url = URL.createObjectURL(await res.blob()); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000); }
function showDevice(d) {
  const body = dialog(d.name); paragraph(body, `Сертификат SHA-256: ${d.id}`, 'mono'); paragraph(body, `${d.ip} · ${d.connected ? 'Подключено' : 'Отключено'} · сервер получил ${bytes(d.received_bytes)}, передал ${bytes(d.sent_bytes)}`,'muted');
  const name = field(body,'Название',d.name); action(body,'Переименовать',async()=> {await api('/api/device',{id:d.id,action:'rename',name:name.value}); $('dialog').close(); await refresh();});
  const controls = document.createElement('div'); controls.className = 'actions'; body.append(controls);
  if (d.access === 'enabled') {
    action(controls,'Конфигурация',()=>download(`/api/export/${d.id}`,'connect-ip-client.json'));
    action(controls,'Сертификат',()=>download(`/api/certificate/${d.id}`,'device.pem'));
    action(controls,'CA',()=>download('/api/ca','ca.pem'));
    action(controls,'Отключить доступ',async()=>confirmAction('Отключить доступ?', 'Активная сессия будет закрыта. Повторное подключение заблокируется и после перезапуска.',()=>api('/api/device',{id:d.id,action:'disable',confirm:true})));
  }
  if (d.access !== 'revoked') action(controls,'Отозвать сертификат',async()=>confirmAction('Отозвать сертификат?', 'Этот сертификат больше нельзя будет зарегистрировать. Активная сессия будет закрыта.',()=>api('/api/device',{id:d.id,action:'revoke',confirm:true})));
  action(controls,'Удалить устройство',async()=>confirmAction('Удалить устройство?', 'Доступ будет отозван. Запись об отзыве сохранится, чтобы удалённый сертификат не смог вернуться.',()=>api('/api/device',{id:d.id,action:'delete',confirm:true})));
  paragraph(body,'Закрытый ключ остаётся на устройстве: device-key.pem. Экспорт содержит только совместимый JSON и пути к локальным файлам. Для исходных устройств используйте их оригинальный сертификат.','field-note');
}
async function enrollment() {
  const data = await api('/api/challenge'), body = dialog('Добавить устройство');
  paragraph(body,'Сначала проверьте владельца устройства вне панели и отпечаток его сертификата. Сертификат выпускается доверенным CA вне панели; новый CSR с этим challenge подтверждает владение закрытым ключом. Challenge действует 5 минут.','muted');
  const challenge = field(body,'Challenge для CN нового CSR',data.challenge); challenge.readOnly = true;
  const pre = document.createElement('pre'); pre.textContent = `openssl req -new -key device-key.pem -out proof.csr -subj "/CN=${data.challenge}"`; body.append(pre);
  const name = field(body,'Название устройства'), ip = field(body,'Назначенный частный IPv4'), csr = field(body,'CSR PEM с указанным challenge', '', true), cert = field(body,'Сертификат клиента PEM', '', true);
  const label = document.createElement('label'), verified = document.createElement('input'); verified.type = 'checkbox'; verified.style.width = 'auto'; label.append(verified, document.createTextNode(' Я проверил владельца устройства и отпечаток сертификата')); body.append(label);
  action(body,'Проверить и добавить',async()=> { if (!verified.checked) throw new Error('Подтвердите проверку устройства'); await api('/api/enroll',{name:name.value,ip:ip.value,csr:csr.value,certificate:cert.value,challenge:data.challenge}); $('dialog').close(); await refresh(); },true);
}
function settings() {
  if (!snapshot) { notice('Сначала получите подтверждённое состояние ядра'); return; }
  const body = dialog('Настройки'), endpoint = field(body,'IP-адрес и порт',snapshot.endpoint), iface = field(body,'Сетевой интерфейс',snapshot.interface), destinations = field(body,'Разрешённые сети — одна на строку',snapshot.destinations.join('\n'),true);
  paragraph(body,'Сетевые параметры можно сохранить только после остановки сервера. Действуют ограничения изолированной лаборатории: частные IPv4 и сети /24 или уже.','field-note');
  action(body,'Сохранить сетевые параметры',async()=> {await api('/api/settings',{endpoint:endpoint.value,interface:iface.value,destinations:destinations.value.split('\n').map(s=>s.trim()).filter(Boolean)}); $('dialog').close(); await refresh();},true);
  paragraph(body,'Авторизация: администратор, сессии 8 часов, 5 попыток входа в минуту. Пароль меняется локально: connect-ui password ui.json, затем перезапуск панели.','field-note');
  paragraph(body,'Журнал: последние 100 событий управления, без секретов, в памяти. Ядро не поддерживает уровни журналирования и безопасное автообновление; эти настройки недоступны. Обновление выполняется вручную из проверенного исходного кода.','field-note');
  action(body,'Сменить тему',async()=>setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
}
$('login-form').onsubmit = async e => { e.preventDefault(); try { const s = await api('/auth/login',{username:$('username').value,password:$('password').value}); csrf=s.csrf; text('login-error',''); signedIn(); await refresh(); } catch (error) { text('login-error',error.message); } };
$('refresh').onclick = refresh;
$('theme').onclick = () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
$('logout').onclick = async () => { try { await api('/auth/logout',{}); signedOut(); } catch(e) { notice(e.message); } };
$('close-dialog').onclick = () => $('dialog').close();
$('settings').onclick = settings;
$('add').onclick = () => enrollment().catch(e=>notice(e.message));
$('logs').onclick = async () => { try { const events = await api('/api/logs'), body=dialog('Журнал управления'), pre=document.createElement('pre'); pre.textContent=events.length ? events.join('\n') : 'Событий пока нет'; body.append(pre); } catch(e) {notice(e.message);} };
$('start').onclick = async () => { if (pending) return; pending=true; try {await api('/api/server',{action:'start'});await refresh();} catch(e) {await refresh();notice(e.message);} finally {pending=false;} };
for (const id of ['stop','restart']) $(id).onclick = () => confirmAction(id==='stop' ? 'Остановить сервер?' : 'Перезапустить сервер?', 'Все активные подключения будут закрыты.',()=>api('/api/server',{action:id,confirm:true}));
(async()=> { try { const s=await api('/auth/session');csrf=s.csrf;signedIn();await refresh(); } catch { signedOut(); } })();
setInterval(()=> {if(csrf && !pending && !$('dialog').open) refresh();},5000);

$('invite').onclick = () => {
  const body = dialog('Одноразовый доступ'), name = field(body,'Название устройства'), ip = field(body,'Назначенный IPv4');
  const note = document.createElement('p'); note.textContent = 'Передайте приглашение только владельцу устройства. Оно действует 5 минут и используется один раз. Windows-клиент создаёт закрытый ключ у себя; панель его не получает.'; body.append(note);
  const create = document.createElement('button'); create.textContent = 'Выдать приглашение'; body.append(create);
  create.onclick = async () => {
    create.disabled = true;
    try {
      const result = await api('/api/invitation',{name:name.value,ip:ip.value});
      const link = field(body,'connect://',result.link,true); link.readOnly = true;
      const res = await fetch('/api/invitation-qr',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Connect-UI':'1','X-CSRF-Token':csrf},body:JSON.stringify({link:result.link})});
      if(!res.ok) throw new Error('Не удалось создать QR');
      const bitmap = await createImageBitmap(await res.blob()), canvas = document.createElement('canvas'); canvas.width = bitmap.width; canvas.height = bitmap.height; canvas.style.maxWidth = '100%'; canvas.getContext('2d').drawImage(bitmap,0,0); bitmap.close(); body.append(canvas);
      const copy=document.createElement('button');copy.textContent='Копировать ссылку';copy.onclick=()=>navigator.clipboard.writeText(result.link).catch(()=>{link.focus();link.select();});body.append(copy);
      const download=document.createElement('button');download.textContent='Сохранить QR';download.onclick=()=>canvas.toBlob(blob=>{const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='connect-invitation.png';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});body.append(download);
      create.remove(); note.textContent='Приглашение выдано. После регистрации устройство появится в общем списке. Потерянный ответ требует нового приглашения; токен повторно не используется.';
    }catch(e){notice(e.message);create.disabled=false;}
  };
};
