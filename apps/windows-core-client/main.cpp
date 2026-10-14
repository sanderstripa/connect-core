#include <windows.h>
#include <d2d1.h>
#include <dwrite.h>
#include <dwmapi.h>
#include <commdlg.h>
#include <shellapi.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <cmath>
#include <algorithm>

constexpr UINT Update = WM_APP + 1, WorkerExit = WM_APP + 2;
struct Snapshot { uint32_t state, code; uint64_t tx, rx, elapsed; uint32_t mode;char endpoint[128];uint64_t dnsRTT; };
static_assert(sizeof(Snapshot)==176);
HWND window; HANDLE input=nullptr, output=nullptr, process=nullptr, job=nullptr;
std::thread reader; Snapshot current{}; bool dark=false, diagnostics=false, shutting=false, coreAlive=false, pendingDNS=false;std::wstring chosenDNS;
float dpi=96; int scroll=0; double rxRate=0,txRate=0; ULONGLONG lastSample=0; uint64_t oldTx=0,oldRx=0;
ID2D1Factory* factory=nullptr; ID2D1HwndRenderTarget* target=nullptr; ID2D1SolidColorBrush* brush=nullptr;
IDWriteFactory* writeFactory=nullptr; IDWriteTextFormat *body=nullptr,*captionFont=nullptr,*title=nullptr,*actionFont=nullptr;
std::vector<std::wstring> logs;
void importLink(const std::wstring& link);
template<class T> void release(T*& p){if(p){p->Release();p=nullptr;}}
std::wstring utf8(const char* p,int n){int len=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,p,n,nullptr,0);std::wstring s(len,L' ');if(len)MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,p,n,s.data(),len);return s;}
bool exactRead(void* data,DWORD size){auto p=static_cast<char*>(data);while(size){DWORD n=0;if(!ReadFile(output,p,size,&n,nullptr)||!n)return false;p+=n;size-=n;}return true;}
bool command(uint8_t kind,const std::string& payload={}){if(!coreAlive||payload.size()>32768)return false;uint8_t h[8]={'C','C',2,kind};uint32_t len=static_cast<uint32_t>(payload.size());memcpy(h+4,&len,4);DWORD n=0;if(!WriteFile(input,h,8,&n,nullptr)||n!=8)return false;if(len&&(!WriteFile(input,payload.data(),len,&n,nullptr)||n!=len))return false;return true;}
void addLog(std::wstring s){if(logs.size()==64)logs.erase(logs.begin());logs.push_back(std::move(s));}
bool startWorker(){
 wchar_t path[32768];DWORD count=GetModuleFileNameW(nullptr,path,32768);if(!count||count==32768)return false;
 std::wstring exe(path,count);exe=exe.substr(0,exe.find_last_of(L"\\/")+1)+L"connect-desktop-core.exe";
 SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE childIn=nullptr,childOut=nullptr;
 if(!CreatePipe(&childIn,&input,&sa,0))return false;
 if(!CreatePipe(&output,&childOut,&sa,0)){CloseHandle(childIn);CloseHandle(input);input=nullptr;return false;}
 SetHandleInformation(input,HANDLE_FLAG_INHERIT,0);SetHandleInformation(output,HANDLE_FLAG_INHERIT,0);
 // Only these two private handles may cross into the worker. No global listener.
 SIZE_T bytes=0;InitializeProcThreadAttributeList(nullptr,1,0,&bytes);std::vector<uint8_t> attributes(bytes);
 STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.lpAttributeList=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
 bool initialized=InitializeProcThreadAttributeList(si.lpAttributeList,1,0,&bytes)!=FALSE;
 HANDLE handles[]={childIn,childOut};bool ok=initialized&&UpdateProcThreadAttribute(si.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,handles,sizeof(handles),nullptr,nullptr);
 si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdInput=childIn;si.StartupInfo.hStdOutput=childOut;si.StartupInfo.hStdError=childOut;
 job=CreateJobObjectW(nullptr,nullptr);JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
 ok=ok&&job&&SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limit,sizeof(limit));
 PROCESS_INFORMATION pi{};std::wstring cmd=L"\""+exe+L"\" --ipc";
 ok=ok&&CreateProcessW(exe.c_str(),cmd.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi);
 if(initialized)DeleteProcThreadAttributeList(si.lpAttributeList);CloseHandle(childIn);CloseHandle(childOut);
 if(ok){if(!AssignProcessToJobObject(job,pi.hProcess)){TerminateProcess(pi.hProcess,1);ok=false;}else{ResumeThread(pi.hThread);process=pi.hProcess;}CloseHandle(pi.hThread);if(!ok)CloseHandle(pi.hProcess);}
 if(!ok){CloseHandle(input);CloseHandle(output);input=output=nullptr;if(job)CloseHandle(job);job=nullptr;return false;}
 coreAlive=true;
 reader=std::thread([](){while(true){uint8_t h[8];if(!exactRead(h,8))break;uint32_t n;memcpy(&n,h+4,4);if(h[0]!='C'||h[1]!='C'||h[2]!=2||h[3]!=128||n!=sizeof(Snapshot))break;auto s=new Snapshot{};if(!exactRead(s,sizeof(*s))){delete s;break;}if(!PostMessageW(window,Update,0,reinterpret_cast<LPARAM>(s))){delete s;break;}}PostMessageW(window,WorkerExit,0,0);});
 return true;
}
void stopWorker(){shutting=true;command(5);if(input){CloseHandle(input);input=nullptr;}if(process&&WaitForSingleObject(process,6000)!=WAIT_OBJECT_0)TerminateJobObject(job,1);if(job){CloseHandle(job);job=nullptr;}if(reader.joinable())reader.join();if(output)CloseHandle(output);if(process)CloseHandle(process);output=process=nullptr;coreAlive=false;MSG m;while(PeekMessageW(&m,window,Update,Update,PM_REMOVE))delete reinterpret_cast<Snapshot*>(m.lParam);}
std::wstring stateText(){if(!coreAlive)return L"Ядро недоступно";switch(current.state){case 0:return L"Добавьте конфигурацию";case 1:if(current.mode==4)return L"Укажите DNS для системного VPN";return current.mode?L"Готов к системному подключению":L"Готов к лабораторному тесту";case 2:return L"Подготовка сети и проверка устройства…";case 3:return current.mode==1?L"Системный IPv4 VPN · CONNECT IP v2":L"CONNECT IP v2 · сеанс установлен";case 6:return L"Ожидание подтверждения устройства в панели…";default:return current.mode==1||current.mode==3?L"Ошибка · проверьте сохранённую защиту сети":L"Подключение завершилось с ошибкой";}}
std::wstring errorText(){switch(current.code){case 1:return L"Конфигурация, сертификат или хранилище недоступны";case 2:return L"Ошибка сети, аутентификации или согласования v2";case 3:return L"Сертификат сервера не прошёл проверку";case 4:return L"Приглашение / QR недействительно или регистрация отклонена";case 5:return L"Нужна проверка / восстановление сети (F10)";case 7:return L"Подтверждение администратора отменено";case 8:return L"DNS-проба не получила корректный ответ";case 11:return L"Укажите DNS перед включением системного VPN";case 12:return L"Проверьте адрес IPv4 DNS или защищённое хранилище";default:return L"Ошибок не зарегистрировано";}}
std::wstring amount(double n){wchar_t b[80];if(n<1024)swprintf_s(b,L"%.0f Б",n);else if(n<1048576)swprintf_s(b,L"%.1f КБ",n/1024);else swprintf_s(b,L"%.1f МБ",n/1048576);return b;}
void text(const std::wstring& s,float x,float y,float width,IDWriteTextFormat* format,D2D1_COLOR_F color,float height=40){brush->SetColor(color);target->DrawTextW(s.c_str(),static_cast<UINT32>(s.size()),format,D2D1::RectF(x,y,x+width,y+height),brush);}
void panel(float x,float y,float w,float h,D2D1_COLOR_F color,float radius=12){brush->SetColor(color);target->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x,y,x+w,y+h),radius,radius),brush);}
void paint(){
 if(!target){RECT r;GetClientRect(window,&r);if(FAILED(factory->CreateHwndRenderTarget(D2D1::RenderTargetProperties(),D2D1::HwndRenderTargetProperties(window,D2D1::SizeU(r.right,r.bottom)),&target)))return;target->SetDpi(dpi,dpi);if(FAILED(target->CreateSolidColorBrush(D2D1::ColorF(0),&brush))){release(target);return;}}
 auto bg=D2D1::ColorF(dark?0x141719:0xf5f6f7), fg=D2D1::ColorF(dark?0xeceded:0x20272b),muted=D2D1::ColorF(dark?0x9da6ad:0x64717b),card=D2D1::ColorF(dark?0x20262a:0xffffff),accent=D2D1::ColorF(dark?0x91b9a9:0x365e50);
 target->BeginDraw();target->SetTransform(D2D1::Matrix3x2F::Translation(0,-static_cast<float>(scroll)));target->Clear(bg);
 text(L"CONNECT CORE",28,25,340,title,fg);panel(394,24,96,34,card,8);text(dark?L"Светлая":L"Тёмная",407,31,80,captionFont,muted);
 text(current.mode?L"СИСТЕМНЫЙ IPv4 VPN · ИЗОЛИРОВАННЫЕ ИСПЫТАНИЯ":L"ЛАБОРАТОРНЫЙ РЕЖИМ · БЕЗ СИСТЕМНОГО VPN",28,76,470,captionFont,accent);
 panel(28,111,462,86,card);text(current.state==6?L"ОТПЕЧАТОК КЛЮЧА ДЛЯ ПОДТВЕРЖДЕНИЯ":L"ТЕКУЩИЙ СЕРВЕР",46,125,420,captionFont,muted);
 size_t len=strnlen_s(current.endpoint,128);if(current.state==6){if(len==64){text(utf8(current.endpoint,32),46,150,420,captionFont,fg);text(utf8(current.endpoint+32,32),46,172,420,captionFont,fg);}else text(L"Создание локального ключа…",46,151,420,body,fg);}else text(len?utf8(current.endpoint,static_cast<int>(len)):L"Конфигурация не добавлена",46,151,420,body,fg);
 panel(28,220,462,74,current.state==3?accent:card,18);
 text(current.mode==3?L"Восстановить сеть":current.state==6?L"Отменить":current.state==3||current.state==2||current.mode==1?L"Отключить":L"Подключить",28,220,462,actionFont,current.state==3?bg:fg,74);
 if(current.state==2){float phase=static_cast<float>(GetTickCount64()%1400)/1400;brush->SetColor(accent);target->FillEllipse(D2D1::Ellipse(D2D1::Point2F(143,256),4+2*std::sin(phase*6.283f),4+2*std::sin(phase*6.283f)),brush);}
 text(stateText(),28,310,462,captionFont,muted);
 panel(28,351,225,76,card);panel(265,351,225,76,card);panel(28,439,225,76,card);panel(265,439,225,76,card);
 text(L"ВХОДЯЩИЙ IP-ТРАФИК",44,362,204,captionFont,muted);text(amount(rxRate)+L"/с",44,386,204,body,fg);
 text(L"ИСХОДЯЩИЙ IP-ТРАФИК",281,362,204,captionFont,muted);text(amount(txRate)+L"/с",281,386,204,body,fg);
 text(L"ЗА СЕАНС · IP-БАЙТЫ",44,450,204,captionFont,muted);text(amount(static_cast<double>(current.tx+current.rx)),44,474,204,body,fg);
 text(current.mode?L"ЗАДЕРЖКА DNS":L"ЗАДЕРЖКА",281,450,204,captionFont,muted);wchar_t latency[64];swprintf_s(latency,L"%.1f мс",current.dnsRTT/1000.0);text(current.dnsRTT?latency:L"Недоступна",281,474,204,body,muted);
 panel(28,539,225,42,card,8);panel(265,539,225,42,card,8);text(L"+  Конфигурация",49,550,198,captionFont,fg);text(L"Диагностика",308,550,170,captionFont,fg);
 text(current.mode?L"Wintun и маршруты · отдельный помощник с UAC.":L"Трафик компьютера не направляется в этот сеанс.",28,600,462,captionFont,muted);text(current.mode?L"IPv6 блокируется. При сбое прямой обход запрещён.":L"Тестовый IP-пакет отправляется только по вашей команде.",28,622,462,captionFont,muted);
 if(diagnostics){panel(28,668,462,190,card);text(L"ДИАГНОСТИКА",44,681,420,captionFont,muted);text(L"Ядро: "+std::wstring(coreAlive?L"работает":L"остановлено")+L" · транспорт: "+(current.state==3?L"QUIC / mTLS":L"не установлен"),44,707,420,captionFont,fg);text(errorText(),44,730,420,captionFont,muted);text(L"Время сеанса: "+std::to_wstring(current.elapsed/1000)+L" с",44,754,420,captionFont,muted);panel(44,792,194,42,bg,8);panel(250,792,222,42,bg,8);text(current.code==5?L"Восстановить сеть":current.mode?L"Проверить DNS":L"Отправить IP-пробу",58,804,182,captionFont,fg);text(L"Копировать журнал",268,804,198,captionFont,fg);}
 if(diagnostics){text(L"БЕЗОПАСНЫЙ ЖУРНАЛ · ПОСЛЕДНИЕ СОБЫТИЯ",28,875,462,captionFont,muted);size_t start=logs.size()>3?logs.size()-3:0;for(size_t i=start;i<logs.size();++i)text(logs[i],28,900+static_cast<float>((i-start)*35),462,captionFont,muted,34);}
 if(target->EndDraw()==D2DERR_RECREATE_TARGET){release(brush);release(target);}
}
void updateScroll(){RECT r;GetClientRect(window,&r);SCROLLINFO s{sizeof(s),SIF_RANGE|SIF_PAGE|SIF_POS};s.nMax=(diagnostics?1024:665)-1;s.nPage=static_cast<UINT>(r.bottom*96/dpi);scroll=std::clamp(scroll,0,std::max(0,s.nMax-static_cast<int>(s.nPage)+1));s.nPos=scroll;SetScrollInfo(window,SB_VERT,&s,TRUE);}
void resizeWindow(){RECT r{0,0,static_cast<LONG>(518*dpi/96),static_cast<LONG>((diagnostics?1024:665)*dpi/96)};AdjustWindowRectExForDpi(&r,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX|WS_VSCROLL,FALSE,0,static_cast<UINT>(dpi));MONITORINFO monitor{sizeof(monitor)};GetMonitorInfoW(MonitorFromWindow(window,MONITOR_DEFAULTTONEAREST),&monitor);int h=std::min<int>(r.bottom-r.top,monitor.rcWork.bottom-monitor.rcWork.top);RECT position;GetWindowRect(window,&position);int y=std::clamp<int>(position.top,monitor.rcWork.top,monitor.rcWork.bottom-h);SetWindowPos(window,nullptr,position.left,y,r.right-r.left,h,SWP_NOZORDER);updateScroll();}
void importConfig(){if(pendingDNS||current.state==2||current.state==3||current.state==6||current.mode==1||current.mode==3){MessageBoxW(window,L"Отключите сеанс перед импортом.",L"CONNECT CORE",MB_OK);return;}wchar_t path[32768]{};OPENFILENAMEW f{sizeof(f)};f.hwndOwner=window;f.lpstrFilter=L"CONNECT IP v2 (*.json)\0*.json\0";f.lpstrFile=path;f.nMaxFile=32768;f.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;if(GetOpenFileNameW(&f)){int n=WideCharToMultiByte(CP_UTF8,0,path,-1,nullptr,0,nullptr,nullptr);std::string p(n,'\0');WideCharToMultiByte(CP_UTF8,0,path,-1,p.data(),n,nullptr,nullptr);p.pop_back();command(1,p);}}
void copyLogs(){std::wstring s=L"CONNECT CORE — safe session diagnostics\r\n";for(const auto& l:logs)s+=l+L"\r\n";s+=errorText()+L"\r\n";if(OpenClipboard(window)){auto mem=GlobalAlloc(GMEM_MOVEABLE,(s.size()+1)*sizeof(wchar_t));if(mem){void* p=GlobalLock(mem);if(p){memcpy(p,s.c_str(),(s.size()+1)*sizeof(wchar_t));GlobalUnlock(mem);EmptyClipboard();if(!SetClipboardData(CF_UNICODETEXT,mem))GlobalFree(mem);}else GlobalFree(mem);}CloseClipboard();}}
std::string encode(const std::wstring& s){int n=WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);std::string p(n,'\0');WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),p.data(),n,nullptr,nullptr);return p;}
void importLink(const std::wstring& link){if(link.size()>4096||link.rfind(L"connect://enroll?",0)!=0){MessageBoxW(window,L"Ожидается одноразовая ссылка connect:// из панели.",L"Импорт",MB_OK);return;}if(pendingDNS||current.state==2||current.state==3||current.state==6||current.mode==1||current.mode==3){MessageBoxW(window,L"Сначала завершите текущий сеанс.",L"Импорт",MB_OK);return;}if(MessageBoxW(window,L"Зарегистрировать устройство по приглашению?\n\nПередавайте ссылку только от вашего администратора. Клиент создаст закрытый ключ локально и передаст серверу подписанный запрос. Ключ не отправляется. Приглашение одноразовое.",L"Регистрация устройства",MB_OKCANCEL|MB_ICONINFORMATION)==IDOK)command(6,encode(link));}
void pasteLink(){if(!OpenClipboard(window))return;std::wstring link;HANDLE mem=GetClipboardData(CF_UNICODETEXT);if(mem){auto p=static_cast<wchar_t*>(GlobalLock(mem));if(p){size_t capacity=GlobalSize(mem)/sizeof(wchar_t);size_t n=wcsnlen_s(p,std::min<size_t>(capacity,4097));if(n<=4096)link.assign(p,n);GlobalUnlock(mem);}}CloseClipboard();importLink(link);}
void importQR(){if(pendingDNS||current.state==2||current.state==3||current.state==6||current.mode==1||current.mode==3)return;wchar_t path[32768]{};OPENFILENAMEW f{sizeof(f)};f.hwndOwner=window;f.lpstrFilter=L"QR PNG / JPEG\0*.png;*.jpg;*.jpeg\0";f.lpstrFile=path;f.nMaxFile=32768;f.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;if(GetOpenFileNameW(&f)&&MessageBoxW(window,L"Прочитать QR и зарегистрировать устройство? Закрытый ключ будет создан и сохранён только на этом компьютере.",L"QR-приглашение",MB_OKCANCEL)==IDOK)command(7,encode(path));}
void chooseImport(){HMENU menu=CreatePopupMenu();AppendMenuW(menu,MF_STRING,1,L"Конфигурация CONNECT IP v2…");AppendMenuW(menu,MF_STRING,2,L"connect:// из буфера обмена");AppendMenuW(menu,MF_STRING,3,L"QR из изображения…");POINT p;GetCursorPos(&p);int action=TrackPopupMenu(menu,TPM_RETURNCMD|TPM_NONOTIFY,p.x,p.y,0,window,nullptr);DestroyMenu(menu);if(action==1)importConfig();else if(action==2)pasteLink();else if(action==3)importQR();}
INT_PTR CALLBACK dnsDialog(HWND h,UINT message,WPARAM wp,LPARAM){
 if(message==WM_INITDIALOG){SendDlgItemMessageW(h,1001,EM_SETLIMITTEXT,15,0);SetFocus(GetDlgItem(h,1001));return FALSE;}
 if(message==WM_COMMAND){if(LOWORD(wp)==IDCANCEL){EndDialog(h,IDCANCEL);return TRUE;}if(LOWORD(wp)==IDOK){wchar_t address[32]{};GetDlgItemTextW(h,1001,address,32);chosenDNS=address;if(chosenDNS.empty()){MessageBoxW(h,L"Введите адрес IPv4 DNS для подключения через туннель.",L"DNS",MB_OK);return TRUE;}for(wchar_t c:chosenDNS)if((c<L'0'||c>L'9')&&c!=L'.'){MessageBoxW(h,L"Нужен числовой адрес IPv4 DNS.",L"DNS",MB_OK);return TRUE;}EndDialog(h,IDOK);return TRUE;}}
 return FALSE;
}
void configureDNS(){if(pendingDNS)return;chosenDNS.clear();if(DialogBoxParamW(GetModuleHandleW(nullptr),MAKEINTRESOURCEW(101),window,dnsDialog,0)==IDOK){pendingDNS=command(9,encode(chosenDNS));}}
void recoverNetwork(){if(MessageBoxW(window,L"Восстановить обычную сеть?\n\nСетевой помощник запросит UAC, удалит только настройки CONNECT CORE и снимет сохранённую блокировку прямого трафика.",L"Восстановление сети",MB_OKCANCEL|MB_ICONINFORMATION)==IDOK){if(!coreAlive){stopWorker();shutting=false;MSG stale;while(PeekMessageW(&stale,window,WorkerExit,WorkerExit,PM_REMOVE)){}if(!startWorker()){addLog(L"Не удалось запустить ядро для восстановления сети");return;}}command(8);}}
bool registerProtocol(){wchar_t path[32768];DWORD n=GetModuleFileNameW(nullptr,path,32768);if(!n||n==32768)return false;std::wstring cmd=L"\""+std::wstring(path,n)+L"\" --import \"%1\"";wchar_t existing[32768]{};DWORD size=sizeof(existing);LSTATUS found=RegGetValueW(HKEY_CLASSES_ROOT,L"connect\\shell\\open\\command",nullptr,RRF_RT_REG_SZ,nullptr,existing,&size);if(found==ERROR_SUCCESS&&cmd!=existing){MessageBoxW(window,L"connect:// уже используется другим приложением. Скопируйте ссылку и импортируйте её через кнопку конфигурации.",L"CONNECT CORE",MB_OK);return false;}HKEY key;DWORD disposition;if(RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\Classes\\connect",0,nullptr,0,KEY_SET_VALUE,nullptr,&key,&disposition)!=ERROR_SUCCESS)return false;const wchar_t label[]=L"URL:CONNECT enrollment";RegSetValueExW(key,nullptr,0,REG_SZ,reinterpret_cast<const BYTE*>(label),sizeof(label));const wchar_t empty[]=L"";RegSetValueExW(key,L"URL Protocol",0,REG_SZ,reinterpret_cast<const BYTE*>(empty),sizeof(empty));RegCloseKey(key);if(RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\Classes\\connect\\shell\\open\\command",0,nullptr,0,KEY_SET_VALUE,nullptr,&key,nullptr)!=ERROR_SUCCESS)return false;LSTATUS result=RegSetValueExW(key,nullptr,0,REG_SZ,reinterpret_cast<const BYTE*>(cmd.c_str()),static_cast<DWORD>((cmd.size()+1)*sizeof(wchar_t)));RegCloseKey(key);return result==ERROR_SUCCESS;}
LRESULT CALLBACK wndproc(HWND h,UINT msg,WPARAM wp,LPARAM lp){switch(msg){
 case WM_PAINT:{PAINTSTRUCT p;BeginPaint(h,&p);paint();EndPaint(h,&p);return 0;}
 case WM_ERASEBKGND:return 1;
 case WM_SETCURSOR:if(LOWORD(lp)==HTCLIENT){POINT p;GetCursorPos(&p);ScreenToClient(h,&p);float x=p.x*96/dpi,y=p.y*96/dpi+scroll;bool clickable=(x>=394&&x<=490&&y>=24&&y<=58)||(x>=28&&x<=490&&y>=220&&y<=294)||(x>=28&&x<=490&&y>=539&&y<=581)||(diagnostics&&x>=44&&x<=472&&y>=792&&y<=834);SetCursor(LoadCursorW(nullptr,clickable?IDC_HAND:IDC_ARROW));return TRUE;}break;
 case WM_SIZE:if(target)target->Resize(D2D1::SizeU(LOWORD(lp),HIWORD(lp)));if(window)updateScroll();return 0;
 case WM_MOUSEWHEEL:scroll-=GET_WHEEL_DELTA_WPARAM(wp)/WHEEL_DELTA*48;updateScroll();InvalidateRect(h,nullptr,FALSE);return 0;
 case WM_VSCROLL:{SCROLLINFO s{sizeof(s),SIF_ALL};GetScrollInfo(h,SB_VERT,&s);switch(LOWORD(wp)){case SB_LINEUP:scroll-=30;break;case SB_LINEDOWN:scroll+=30;break;case SB_PAGEUP:scroll-=s.nPage;break;case SB_PAGEDOWN:scroll+=s.nPage;break;case SB_THUMBTRACK:scroll=s.nTrackPos;break;}updateScroll();InvalidateRect(h,nullptr,FALSE);return 0;}
 case WM_DPICHANGED:{dpi=static_cast<float>(HIWORD(wp));if(target)target->SetDpi(dpi,dpi);auto r=reinterpret_cast<RECT*>(lp);SetWindowPos(h,nullptr,r->left,r->top,r->right-r->left,r->bottom-r->top,SWP_NOZORDER);return 0;}
 case WM_TIMER:if(current.state==2)InvalidateRect(h,nullptr,FALSE);return 0;
 case Update:{auto p=reinterpret_cast<Snapshot*>(lp);if(pendingDNS&&(p->state==2||p->state==3||p->state==4||p->code==12))pendingDNS=false;if(p->state==6&&strnlen_s(p->endpoint,128)==64&&memcmp(p->endpoint,current.endpoint,128)!=0)addLog(L"Отпечаток публичного ключа устройства: "+utf8(p->endpoint,64));ULONGLONG now=GetTickCount64();if(lastSample&&now>lastSample&&p->tx>=oldTx&&p->rx>=oldRx){txRate=static_cast<double>(p->tx-oldTx)*1000/(now-lastSample);rxRate=static_cast<double>(p->rx-oldRx)*1000/(now-lastSample);}else txRate=rxRate=0;lastSample=now;oldTx=p->tx;oldRx=p->rx;if(p->state!=current.state||p->code!=current.code){current=*p;addLog(stateText()+L" · "+errorText());if(current.state==2)SetTimer(h,1,40,nullptr);else KillTimer(h,1);}else current=*p;delete p;InvalidateRect(h,nullptr,FALSE);return 0;}
 case WorkerExit:if(!shutting){coreAlive=false;current.state=4;current.code=current.mode?5:2;if(current.mode)current.mode=3;if(job)TerminateJobObject(job,1);KillTimer(h,1);txRate=rxRate=0;addLog(L"Ядро завершилось; прямой обход не выполняется");InvalidateRect(h,nullptr,FALSE);}return 0;
 case WM_KEYDOWN:{if(wp=='V'&&(GetKeyState(VK_CONTROL)&0x8000))pasteLink();else if(wp==VK_F2)importConfig();else if(wp==VK_F9)registerProtocol();else if(wp==VK_F10)recoverNetwork();else if(wp==VK_ESCAPE)command(3);else if(wp==VK_F6){diagnostics=!diagnostics;resizeWindow();}else if(wp==VK_F8){LPARAM click=MAKELPARAM(static_cast<int>(430*dpi/96),static_cast<int>((40-scroll)*dpi/96));SendMessageW(h,WM_LBUTTONUP,0,click);}else if(wp==VK_SPACE){LPARAM click=MAKELPARAM(static_cast<int>(259*dpi/96),static_cast<int>((257-scroll)*dpi/96));SendMessageW(h,WM_LBUTTONUP,0,click);}InvalidateRect(h,nullptr,FALSE);return 0;}
 case WM_COPYDATA:{auto data=reinterpret_cast<COPYDATASTRUCT*>(lp);if(data&&data->dwData==1&&data->cbData>=2&&data->cbData<=8194&&data->cbData%2==0){auto s=static_cast<const wchar_t*>(data->lpData);size_t n=data->cbData/2;if(s[n-1]==0){importLink(std::wstring(s,n-1));return TRUE;}}return FALSE;}
 case WM_LBUTTONUP:{float x=static_cast<short>(LOWORD(lp))*96/dpi,y=static_cast<short>(HIWORD(lp))*96/dpi+scroll;
  if(x>=394&&x<=490&&y>=24&&y<=58){dark=!dark;BOOL v=dark;DwmSetWindowAttribute(h,20,&v,sizeof(v));HKEY key;if(RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\ConnectCoreLab",0,nullptr,0,KEY_SET_VALUE,nullptr,&key,nullptr)==ERROR_SUCCESS){DWORD value=dark;RegSetValueExW(key,L"Dark",0,REG_DWORD,reinterpret_cast<BYTE*>(&value),4);RegCloseKey(key);}}
  else if(x>=28&&x<=490&&y>=220&&y<=294){if(pendingDNS){}else if(current.mode==4)configureDNS();else if(current.mode==3)recoverNetwork();else if(current.state==3||current.state==2||current.state==6||current.mode==1)command(3);else if(current.state!=0&&coreAlive){if(MessageBoxW(h,current.mode?L"Включить системный IPv4 VPN в изолированной среде? Wintun, DNS, маршруты и защитную блокировку настроит отдельный помощник после UAC. При сбое прямой трафик останется заблокирован до явного отключения или восстановления.":L"Запустить лабораторный CONNECT IP v2 сеанс?\n\nСистемный VPN не включается. Маршруты, DNS и Wintun не изменяются. Подключение использует сервер из импортированной конфигурации.",L"Лабораторный режим",MB_OKCANCEL|MB_ICONINFORMATION)==IDOK)command(2);}}
  else if(y>=539&&y<=581){if(x>=28&&x<=253)chooseImport();else if(x>=265&&x<=490){diagnostics=!diagnostics;resizeWindow();}}
  else if(diagnostics&&y>=792&&y<=834){if(x>=44&&x<=238){if(current.code==5)recoverNetwork();else{command(4);addLog(current.mode?L"Запрошена DNS-проба через системный туннель":L"Запрошена IP-проба через CONNECT; ответ не гарантирован");}}else if(x>=250&&x<=472)copyLogs();}
  InvalidateRect(h,nullptr,FALSE);return 0;}
 case WM_CLOSE:stopWorker();DestroyWindow(h);return 0;
 case WM_DESTROY:PostQuitMessage(0);return 0;
 }return DefWindowProcW(h,msg,wp,lp);}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show){
 int argc=0;LPWSTR* argv=CommandLineToArgvW(GetCommandLineW(),&argc);std::wstring incoming;bool registration=argc==2&&std::wstring(argv[1])==L"--register-protocol";if(argc==3&&std::wstring(argv[1])==L"--import")incoming=argv[2];if(argv)LocalFree(argv);if(registration)return registerProtocol()?0:1;
 HANDLE singleton=CreateMutexW(nullptr,FALSE,L"Local\\ConnectCoreLabUI");if(singleton&&GetLastError()==ERROR_ALREADY_EXISTS){HWND existing=FindWindowW(L"ConnectCoreLabWindow",nullptr);if(existing&&!incoming.empty()&&incoming.size()<=4096){COPYDATASTRUCT data{1,static_cast<DWORD>((incoming.size()+1)*2),incoming.data()};DWORD_PTR ignored;SendMessageTimeoutW(existing,WM_COPYDATA,0,reinterpret_cast<LPARAM>(&data),SMTO_ABORTIFHUNG,10000,&ignored);SetForegroundWindow(existing);}CloseHandle(singleton);return 0;}
 CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
 if(FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED,&factory))||FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED,__uuidof(IDWriteFactory),reinterpret_cast<IUnknown**>(&writeFactory))))return 1;
 auto font=[](float size,DWRITE_FONT_WEIGHT weight,IDWriteTextFormat** out){return writeFactory->CreateTextFormat(L"Segoe UI Variable",nullptr,weight,DWRITE_FONT_STYLE_NORMAL,DWRITE_FONT_STRETCH_NORMAL,size,L"ru-RU",out);};
 if(FAILED(font(18,DWRITE_FONT_WEIGHT_MEDIUM,&body))||FAILED(font(12,DWRITE_FONT_WEIGHT_NORMAL,&captionFont))||FAILED(font(24,DWRITE_FONT_WEIGHT_SEMI_BOLD,&title))||FAILED(font(20,DWRITE_FONT_WEIGHT_MEDIUM,&actionFont)))return 1;
 actionFont->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);actionFont->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
 DWORD value=0,size=4;if(RegGetValueW(HKEY_CURRENT_USER,L"Software\\ConnectCoreLab",L"Dark",RRF_RT_REG_DWORD,nullptr,&value,&size)==ERROR_SUCCESS)dark=value!=0;
 WNDCLASSW c{};c.hInstance=instance;c.lpfnWndProc=wndproc;c.lpszClassName=L"ConnectCoreLabWindow";c.hCursor=LoadCursor(nullptr,IDC_ARROW);RegisterClassW(&c);
 window=CreateWindowExW(0,c.lpszClassName,L"CONNECT CORE",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX|WS_VSCROLL,CW_USEDEFAULT,CW_USEDEFAULT,540,720,nullptr,nullptr,instance,nullptr);if(!window)return 1;dpi=static_cast<float>(GetDpiForWindow(window));resizeWindow();BOOL v=dark;DwmSetWindowAttribute(window,20,&v,sizeof(v));
 if(!startWorker())addLog(L"Не удалось запустить connect-desktop-core.exe");ShowWindow(window,show);
 if(!incoming.empty())importLink(incoming);
 MSG m;while(GetMessageW(&m,nullptr,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}release(brush);release(target);release(body);release(captionFont);release(title);release(actionFont);release(writeFactory);release(factory);if(singleton)CloseHandle(singleton);CoUninitialize();return 0;
}
