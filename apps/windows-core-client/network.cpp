// CONNECT's elevated network capability. No TLS credentials, shell commands,
// browser, public listener or arbitrary file/route operations are accepted.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <fwpmu.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <wintrust.h>
#include <softpub.h>
#include <setupapi.h>
#include <devguid.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <array>
#include <condition_variable>
#include "pipe_io.h"

namespace {
constexpr uint8_t Configure=32,FromTun=33,ToTun=34,Exit=5,Status=128;
constexpr DWORD Mtu=1100;
const GUID Sublayer={0x304497e9,0x426e,0x4f42,{0x8a,0x25,0x3a,0x88,0x52,0x5e,0x71,0xc0}};
const wchar_t* Journal=L"SOFTWARE\\ConnectCoreLab\\NetworkJournal";
HANDLE pipe=INVALID_HANDLE_VALUE,engine=nullptr,permitEngine=nullptr,adapter=nullptr,session=nullptr,worker=nullptr;

HMODULE wintun=nullptr;NET_LUID luid{};GUID adapterGuid{};MIB_IPFORWARD_ROW2 endpointRoute{};bool ownEndpoint=false,guard=false;
std::mutex outputMutex;std::atomic<bool> stopping=false;
DWORD stage=0;std::atomic<DWORD> systemError=0;std::atomic<uint64_t> rawPackets=0,rawBytes=0,polls=0,ringDrops=0;
std::atomic<uint64_t> pipePackets=0,pipeNanos=0,pipeMaxNanos=0;
std::atomic<uint64_t> shortPackets=0,oversizedPackets=0,helperQueueDrops=0;
// Drain/release the kernel ring independently of a slow private pipe reader.
// Fixed storage, bounded drops, and no TLS keys in this privileged process.
struct QueuedTunPacket { DWORD size=0; BYTE bytes[Mtu]{}; };
std::array<QueuedTunPacket,4096> tunQueue;
size_t queueHead=0,queueTail=0,queueCount=0;
std::mutex queueMutex;
std::condition_variable queueReady;
void stopPacketQueue(){
 {std::lock_guard<std::mutex> lock(queueMutex);stopping=true;}
 queueReady.notify_all();
}
HANDLE (WINAPI *createAdapter)(LPCWSTR,LPCWSTR,const GUID*);
void (WINAPI *closeAdapter)(HANDLE);
void (WINAPI *getLuid)(HANDLE,NET_LUID*);
HANDLE (WINAPI *startSession)(HANDLE,DWORD);
void (WINAPI *endSession)(HANDLE);
BYTE* (WINAPI *receivePacket)(HANDLE,DWORD*);
void (WINAPI *releasePacket)(HANDLE,BYTE*);
BYTE* (WINAPI *allocatePacket)(HANDLE,DWORD);
void (WINAPI *sendPacket)(HANDLE,BYTE*);
HANDLE (WINAPI *readEvent)(HANDLE);
#pragma pack(push,1)
struct Plan {uint32_t version,endpoint,device,dns;uint16_t port,mode;};
#pragma pack(pop)
static_assert(sizeof(Plan)==20);
GUID filterKey(int n){GUID g=Sublayer;g.Data4[7]=static_cast<BYTE>(0xc1+n);return g;}
void check(DWORD value){if(value!=ERROR_SUCCESS)throw value;}
// A synchronous pipe handle serializes reads and writes across threads. The
// helper must receive commands while concurrently forwarding Windows packets.
bool transfer(bool reading,void* bytes,DWORD size){
 if(connect_pipe::transfer(pipe,reading,bytes,size))return true;
 DWORD error=GetLastError(),expected=0;systemError.compare_exchange_strong(expected,error?error:ERROR_BROKEN_PIPE);return false;
}
bool readExact(void* p,DWORD size){return transfer(true,p,size);}
bool frame(uint8_t kind,const void* p,DWORD size){std::lock_guard<std::mutex> lock(outputMutex);BYTE h[8]={'C','C',2,kind};memcpy(h+4,&size,4);return transfer(false,h,8)&&(!size||transfer(false,const_cast<void*>(p),size));}
void status(uint32_t state,uint32_t code=0){BYTE b[176]{};DWORD error=systemError.load();memcpy(b,&state,4);memcpy(b+4,&code,4);memcpy(b+8,&error,4);memcpy(b+16,&stage,4);uint32_t mode=guard?1:0;memcpy(b+32,&mode,4);frame(Status,b,sizeof(b));}
std::wstring executable(){wchar_t path[32768];DWORD n=GetModuleFileNameW(nullptr,path,32768);if(!n||n==32768)throw DWORD(ERROR_BAD_PATHNAME);return std::wstring(path,n);}
std::wstring adjacent(const wchar_t* name){auto p=executable();return p.substr(0,p.find_last_of(L"\\/")+1)+name;}
bool privateIP(uint32_t ip){uint32_t h=ntohl(ip);return (h>>24)==10||(h>>20)==0xac1||(h>>16)==0xc0a8;}
bool unicast(uint32_t ip){uint32_t h=ntohl(ip);return h&&h!=0xffffffff&&(h>>24)!=127&&(h>>28)<14&&(h>>16)!=0xa9fe;}
bool loopback(uint32_t ip){return (ntohl(ip)>>24)==127;}
void validate(const Plan& p){if(p.version!=1||p.mode!=1||!p.port||(!unicast(p.endpoint)&&!loopback(p.endpoint))||!privateIP(p.device)||!unicast(p.dns)||p.device==p.endpoint||p.dns==p.device||p.dns==p.endpoint)throw DWORD(ERROR_INVALID_DATA);}
void trustedDLL(){
 auto path=adjacent(L"wintun.dll");WINTRUST_FILE_INFO file{sizeof(file)};file.pcwszFilePath=path.c_str();WINTRUST_DATA trust{sizeof(trust)};trust.dwUIChoice=WTD_UI_NONE;trust.fdwRevocationChecks=WTD_REVOKE_NONE;trust.dwUnionChoice=WTD_CHOICE_FILE;trust.pFile=&file;trust.dwStateAction=WTD_STATEACTION_VERIFY;trust.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL;GUID action=WINTRUST_ACTION_GENERIC_VERIFY_V2;
 LONG result=WinVerifyTrust(nullptr,&action,&trust);bool publisher=false;
 if(result==ERROR_SUCCESS){auto provider=WTHelperProvDataFromStateData(trust.hWVTStateData);auto signer=WTHelperGetProvSignerFromChain(provider,0,FALSE,0);if(signer&&signer->csCertChain){wchar_t subject[512]{};CertGetNameStringW(signer->pasCertChain[0].pCert,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,nullptr,subject,512);publisher=std::wstring(subject)==L"WireGuard LLC";}}
 trust.dwStateAction=WTD_STATEACTION_CLOSE;WinVerifyTrust(nullptr,&action,&trust);if(result!=ERROR_SUCCESS||!publisher)throw DWORD(TRUST_E_BAD_DIGEST);
 wintun=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!wintun)throw GetLastError();
#define LOAD(name,exportName) name=reinterpret_cast<decltype(name)>(GetProcAddress(wintun,exportName));if(!name)throw DWORD(ERROR_PROC_NOT_FOUND)
 LOAD(createAdapter,"WintunCreateAdapter");LOAD(closeAdapter,"WintunCloseAdapter");LOAD(getLuid,"WintunGetAdapterLUID");LOAD(startSession,"WintunStartSession");LOAD(endSession,"WintunEndSession");LOAD(receivePacket,"WintunReceivePacket");LOAD(releasePacket,"WintunReleaseReceivePacket");LOAD(allocatePacket,"WintunAllocateSendPacket");LOAD(sendPacket,"WintunSendPacket");LOAD(readEvent,"WintunGetReadWaitEvent");
#undef LOAD
}
void setJournal(const wchar_t* name,DWORD type,const void* data,DWORD size){HKEY key;check(RegCreateKeyExW(HKEY_LOCAL_MACHINE,Journal,0,nullptr,0,KEY_SET_VALUE,nullptr,&key,nullptr));LSTATUS e=RegSetValueExW(key,name,0,type,static_cast<const BYTE*>(data),size);if(e==ERROR_SUCCESS)e=RegFlushKey(key);RegCloseKey(key);check(e);}
bool readJournal(const wchar_t* name,DWORD type,void* data,DWORD size){DWORD n=size;return RegGetValueW(HKEY_LOCAL_MACHINE,Journal,name,type,nullptr,data,&n)==ERROR_SUCCESS&&n==size;}
void checkpoint(){
 DWORD pid=GetCurrentProcessId();FILETIME created,exited,kernel,user;check(GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)?0:GetLastError());setJournal(L"HelperPID",REG_DWORD,&pid,4);setJournal(L"Created",REG_BINARY,&created,sizeof(created));setJournal(L"Luid",REG_BINARY,&luid,sizeof(luid));setJournal(L"AdapterGUID",REG_BINARY,&adapterGuid,sizeof(adapterGuid));DWORD owned=ownEndpoint;setJournal(L"OwnEndpoint",REG_DWORD,&owned,4);if(ownEndpoint)setJournal(L"EndpointRoute",REG_BINARY,&endpointRoute,sizeof(endpointRoute));
}
FWPM_FILTER_CONDITION0 flags(){FWPM_FILTER_CONDITION0 c{};c.fieldKey=FWPM_CONDITION_FLAGS;c.matchType=FWP_MATCH_FLAGS_ALL_SET;c.conditionValue.type=FWP_UINT32;c.conditionValue.uint32=FWP_CONDITION_FLAG_IS_LOOPBACK;return c;}
void addFilter(int id,const GUID& layer,FWP_ACTION_TYPE action,UINT64 weight,FWPM_FILTER_CONDITION0* conditions=nullptr,DWORD count=0){
 FWPM_FILTER0 f{};f.filterKey=filterKey(id);f.displayData.name=const_cast<wchar_t*>(L"CONNECT CORE — fail-closed IPv4 VPN");bool temporary=action==FWP_ACTION_PERMIT&&weight<100;f.flags=temporary?0:FWPM_FILTER_FLAG_PERSISTENT;f.layerKey=layer;f.subLayerKey=Sublayer;f.weight.type=FWP_UINT64;f.weight.uint64=&weight;f.action.type=action;f.filterCondition=conditions;f.numFilterConditions=count;check(FwpmFilterAdd0(temporary?permitEngine:engine,&f,nullptr,nullptr));
}
void installGuard(const Plan& p){
 FWPM_SUBLAYER0* existing=nullptr;DWORD e=FwpmSubLayerGetByKey0(engine,&Sublayer,&existing);if(e==ERROR_SUCCESS){FwpmFreeMemory0(reinterpret_cast<void**>(&existing));throw DWORD(ERROR_ALREADY_EXISTS);}if(e!=FWP_E_SUBLAYER_NOT_FOUND)throw e;
 auto local=flags();
 check(FwpmTransactionBegin0(engine,0));try{
  FWPM_SUBLAYER0 sub{};sub.subLayerKey=Sublayer;sub.displayData.name=const_cast<wchar_t*>(L"CONNECT CORE network protection");sub.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;sub.weight=65535;check(FwpmSubLayerAdd0(engine,&sub,nullptr));
  addFilter(0,FWPM_LAYER_OUTBOUND_TRANSPORT_V4,FWP_ACTION_PERMIT,100,&local,1);addFilter(1,FWPM_LAYER_OUTBOUND_TRANSPORT_V6,FWP_ACTION_PERMIT,100,&local,1);
  addFilter(4,FWPM_LAYER_OUTBOUND_TRANSPORT_V4,FWP_ACTION_BLOCK,1);addFilter(5,FWPM_LAYER_OUTBOUND_TRANSPORT_V6,FWP_ACTION_BLOCK,1);
  addFilter(6,FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWP_ACTION_PERMIT,100,&local,1);addFilter(7,FWPM_LAYER_ALE_AUTH_CONNECT_V6,FWP_ACTION_PERMIT,100,&local,1);
  addFilter(10,FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWP_ACTION_BLOCK,1);addFilter(11,FWPM_LAYER_ALE_AUTH_CONNECT_V6,FWP_ACTION_BLOCK,1);
  addFilter(12,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,FWP_ACTION_PERMIT,100,&local,1);addFilter(13,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,FWP_ACTION_PERMIT,100,&local,1);
  addFilter(16,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,FWP_ACTION_BLOCK,1);addFilter(17,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,FWP_ACTION_BLOCK,1);
  check(FwpmTransactionCommit0(engine));guard=true;
 }catch(...){FwpmTransactionAbort0(engine);throw;}
 // Only default-deny and loopback rules persist. Tunnel/endpoint permits are
 // owned by this helper's dynamic session, so a crash cannot leave a stale LUID
 // permit that accidentally matches a subsequently created network adapter.
 FWPM_SESSION0 sessionPolicy{};sessionPolicy.flags=FWPM_SESSION_FLAG_DYNAMIC;check(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&sessionPolicy,&permitEngine));
 FWPM_FILTER_CONDITION0 tun{};tun.fieldKey=FWPM_CONDITION_IP_LOCAL_INTERFACE;tun.matchType=FWP_MATCH_EQUAL;tun.conditionValue.type=FWP_UINT64;tun.conditionValue.uint64=&luid.Value;
 FWPM_FILTER_CONDITION0 remote[3]{};remote[0].fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;remote[0].matchType=FWP_MATCH_EQUAL;remote[0].conditionValue.type=FWP_UINT32;remote[0].conditionValue.uint32=ntohl(p.endpoint);remote[1].fieldKey=FWPM_CONDITION_IP_PROTOCOL;remote[1].matchType=FWP_MATCH_EQUAL;remote[1].conditionValue.type=FWP_UINT8;remote[1].conditionValue.uint8=IPPROTO_UDP;remote[2].fieldKey=FWPM_CONDITION_IP_REMOTE_PORT;remote[2].matchType=FWP_MATCH_EQUAL;remote[2].conditionValue.type=FWP_UINT16;remote[2].conditionValue.uint16=p.port;
 FWP_BYTE_BLOB* app=nullptr;auto core=adjacent(L"connect-desktop-core.exe");check(FwpmGetAppIdFromFileName0(core.c_str(),&app));
 check(FwpmTransactionBegin0(permitEngine,0));try{
  addFilter(2,FWPM_LAYER_OUTBOUND_TRANSPORT_V4,FWP_ACTION_PERMIT,80,&tun,1);addFilter(3,FWPM_LAYER_OUTBOUND_TRANSPORT_V4,FWP_ACTION_PERMIT,70,remote,3);
  addFilter(8,FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWP_ACTION_PERMIT,80,&tun,1);addFilter(14,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,FWP_ACTION_PERMIT,80,&tun,1);
  FWPM_FILTER_CONDITION0 endpointOnly[4]{};memcpy(endpointOnly,remote,sizeof(remote));endpointOnly[3].fieldKey=FWPM_CONDITION_ALE_APP_ID;endpointOnly[3].matchType=FWP_MATCH_EQUAL;endpointOnly[3].conditionValue.type=FWP_BYTE_BLOB_TYPE;endpointOnly[3].conditionValue.byteBlob=app;
  addFilter(9,FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWP_ACTION_PERMIT,70,endpointOnly,4);addFilter(15,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,FWP_ACTION_PERMIT,70,endpointOnly,4);
  check(FwpmTransactionCommit0(permitEngine));
 }catch(...){FwpmTransactionAbort0(permitEngine);FwpmFreeMemory0(reinterpret_cast<void**>(&app));throw;}
 FwpmFreeMemory0(reinterpret_cast<void**>(&app));
}
void closePermits(){if(permitEngine){HANDLE owned=permitEngine;permitEngine=nullptr;check(FwpmEngineClose0(owned));}}
void removeGuard(){closePermits();check(FwpmTransactionBegin0(engine,0));try{for(int i=0;i<18;++i){auto key=filterKey(i);DWORD e=FwpmFilterDeleteByKey0(engine,&key);if(e!=ERROR_SUCCESS&&e!=FWP_E_FILTER_NOT_FOUND)throw e;}DWORD e=FwpmSubLayerDeleteByKey0(engine,&Sublayer);if(e!=ERROR_SUCCESS&&e!=FWP_E_SUBLAYER_NOT_FOUND)throw e;check(FwpmTransactionCommit0(engine));guard=false;}catch(...){FwpmTransactionAbort0(engine);throw;}}
SOCKADDR_INET ipv4(uint32_t ip){SOCKADDR_INET a{};a.Ipv4.sin_family=AF_INET;a.Ipv4.sin_addr.S_un.S_addr=ip;return a;}
// The worker pins its UDP socket with IP_UNICAST_IF before the split routes
// become active. Do not exclude the entire server IP: TCP panels on that IP
// must use the tunnel and remain subject to the fail-closed guard.
void configure(const Plan& p){
 stage=6;
 MIB_IPINTERFACE_ROW row{};InitializeIpInterfaceEntry(&row);row.Family=AF_INET;row.InterfaceLuid=luid;check(GetIpInterfaceEntry(&row));row.SitePrefixLength=0;row.NlMtu=Mtu;row.UseAutomaticMetric=FALSE;row.Metric=0;row.DadTransmits=0;row.RouterDiscoveryBehavior=RouterDiscoveryDisabled;check(SetIpInterfaceEntry(&row));
 MIB_UNICASTIPADDRESS_ROW address{};InitializeUnicastIpAddressEntry(&address);address.InterfaceLuid=luid;address.Address=ipv4(p.device);address.OnLinkPrefixLength=32;address.PrefixOrigin=IpPrefixOriginManual;address.SuffixOrigin=IpSuffixOriginManual;address.ValidLifetime=INFINITE;address.PreferredLifetime=INFINITE;address.DadState=IpDadStatePreferred;check(CreateUnicastIpAddressEntry(&address));
 for(int i=0;i<100;++i){auto current=address;if(GetUnicastIpAddressEntry(&current)==ERROR_SUCCESS&&current.DadState==IpDadStatePreferred)break;if(i==99)throw DWORD(ERROR_TIMEOUT);Sleep(50);}
 stage=7;wchar_t dns[32];InetNtopW(AF_INET,const_cast<uint32_t*>(&p.dns),dns,32);DNS_INTERFACE_SETTINGS settings{};settings.Version=DNS_INTERFACE_SETTINGS_VERSION1;settings.Flags=DNS_SETTING_NAMESERVER|DNS_SETTING_REGISTRATION_ENABLED|DNS_SETTINGS_ENABLE_LLMNR;settings.NameServer=dns;settings.RegistrationEnabled=FALSE;settings.EnableLLMNR=FALSE;check(SetInterfaceDnsSettings(adapterGuid,&settings));
 stage=8;
 for(int half=0;half<2;++half){MIB_IPFORWARD_ROW2 route{};InitializeIpForwardEntry(&route);route.InterfaceLuid=luid;route.DestinationPrefix.Prefix=ipv4(half?htonl(0x80000000):0);route.DestinationPrefix.PrefixLength=1;route.NextHop=ipv4(0);route.Metric=0;route.Protocol=MIB_IPPROTO_NETMGMT;route.ValidLifetime=INFINITE;route.PreferredLifetime=INFINITE;check(CreateIpForwardEntry2(&route));}
}
void closeTun(){if(session){endSession(session);session=nullptr;}if(adapter){closeAdapter(adapter);adapter=nullptr;}}
void cleanup(){
 // No existing adapter is changed. Closing the owned Wintun deletes its routes,
 // IP and DNS. Validate a persisted endpoint route before removing it.
 closeTun();if(ownEndpoint){auto current=endpointRoute;DWORD e=GetIpForwardEntry2(&current);if(e==ERROR_SUCCESS){if(current.InterfaceLuid.Value!=endpointRoute.InterfaceLuid.Value||memcmp(&current.NextHop,&endpointRoute.NextHop,sizeof(current.NextHop))||current.Metric!=endpointRoute.Metric)throw DWORD(ERROR_INVALID_DATA);check(DeleteIpForwardEntry2(&endpointRoute));}else if(e!=ERROR_NOT_FOUND)throw e;ownEndpoint=false;}
 removeGuard();DWORD removed=RegDeleteTreeW(HKEY_LOCAL_MACHINE,Journal);if(removed!=ERROR_FILE_NOT_FOUND)check(removed);
}
bool ownedInterfacePresent(const GUID& expected,NET_LUID old){
 PMIB_IF_TABLE2 table=nullptr;check(GetIfTable2(&table));bool present=false,mismatch=false;
 for(ULONG i=0;i<table->NumEntries;++i){const auto& row=table->Table[i];bool sameGuid=memcmp(&expected,&row.InterfaceGuid,sizeof(expected))==0;bool sameLuid=row.InterfaceLuid.Value==old.Value;if(sameGuid||sameLuid){if(!sameGuid||!sameLuid)mismatch=true;else present=true;}}
 FreeMibTable(table);if(mismatch)throw DWORD(ERROR_INVALID_DATA);return present;
}
void removeOwnedAdapter(const GUID& expected,NET_LUID old){
 wchar_t guid[64]{};if(!StringFromGUID2(expected,guid,64))throw DWORD(ERROR_INVALID_DATA);
 // A crashed software-device owner can leave a non-present PnP instance while
 // its interface row remains. Include orphaned instances, matching only the
 // exact journaled GUID already checked against its LUID.
 HDEVINFO devices=SetupDiGetClassDevsW(&GUID_DEVCLASS_NET,nullptr,nullptr,0);if(devices==INVALID_HANDLE_VALUE)throw GetLastError();
 bool found=false;DWORD error=ERROR_NOT_FOUND;
 for(DWORD i=0;;++i){
  SP_DEVINFO_DATA device{sizeof(device)};if(!SetupDiEnumDeviceInfo(devices,i,&device))break;
  HKEY key=SetupDiOpenDevRegKey(devices,&device,DICS_FLAG_GLOBAL,0,DIREG_DRV,KEY_QUERY_VALUE);if(key==INVALID_HANDLE_VALUE)continue;
  wchar_t instance[128]{};DWORD size=sizeof(instance),type=0;LSTATUS read=RegQueryValueExW(key,L"NetCfgInstanceId",nullptr,&type,reinterpret_cast<BYTE*>(instance),&size);RegCloseKey(key);
  if(read!=ERROR_SUCCESS||type!=REG_SZ||size<sizeof(wchar_t)||size>sizeof(instance)||size%sizeof(wchar_t)||instance[size/sizeof(wchar_t)-1]!=0||_wcsicmp(instance,guid))continue;
  found=true;SP_DEVINSTALL_PARAMS_W install{sizeof(install)};if(!SetupDiGetDeviceInstallParamsW(devices,&device,&install)){error=GetLastError();break;}install.Flags|=DI_QUIETINSTALL;install.hwndParent=nullptr;if(!SetupDiSetDeviceInstallParamsW(devices,&device,&install)){error=GetLastError();break;}SP_REMOVEDEVICE_PARAMS removal{};removal.ClassInstallHeader.cbSize=sizeof(SP_CLASSINSTALL_HEADER);removal.ClassInstallHeader.InstallFunction=DIF_REMOVE;removal.Scope=DICS_FLAG_GLOBAL;
  if(!SetupDiSetClassInstallParamsW(devices,&device,&removal.ClassInstallHeader,sizeof(removal))||!SetupDiCallClassInstaller(DIF_REMOVE,devices,&device)){error=GetLastError();break;}
  error=ERROR_SUCCESS;break;
 }
 SetupDiDestroyDeviceInfoList(devices);
 // Closing a crashed helper can asynchronously remove its software device
 // between the interface inventory and PnP enumeration/removal. Success still
 // requires the exact journaled GUID/LUID to be absent, never merely an API
 // error or a live process. Identity mismatches retain the guard as before.
 for(int i=0;i<100;++i){if(!ownedInterfacePresent(expected,old))return;Sleep(100);}
 if(!found||error)throw error;
 throw DWORD(ERROR_TIMEOUT);
}
void recover(){
 stage=10;
 DWORD pid=0;FILETIME stored{};if(readJournal(L"HelperPID",RRF_RT_REG_DWORD,&pid,4)&&readJournal(L"Created",RRF_RT_REG_BINARY,&stored,sizeof(stored))){HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);if(p){FILETIME c,e,k,u;if(GetProcessTimes(p,&c,&e,&k,&u)&&memcmp(&c,&stored,sizeof(c))==0&&WaitForSingleObject(p,0)==WAIT_TIMEOUT){CloseHandle(p);throw DWORD(ERROR_BUSY);}CloseHandle(p);}}
 DWORD owned=0;if(readJournal(L"OwnEndpoint",RRF_RT_REG_DWORD,&owned,4)&&owned){if(!readJournal(L"EndpointRoute",RRF_RT_REG_BINARY,&endpointRoute,sizeof(endpointRoute))||endpointRoute.DestinationPrefix.Prefix.si_family!=AF_INET||endpointRoute.DestinationPrefix.PrefixLength!=32||!endpointRoute.InterfaceLuid.Value)throw DWORD(ERROR_INVALID_DATA);ownEndpoint=true;}
 NET_LUID old{};GUID expected{};if(readJournal(L"Luid",RRF_RT_REG_BINARY,&old,sizeof(old))&&readJournal(L"AdapterGUID",RRF_RT_REG_BINARY,&expected,sizeof(expected))){stage=11;if(ownedInterfacePresent(expected,old)){stage=12;removeOwnedAdapter(expected,old);}}
 stage=13;
 cleanup();
}
void writePackets(){
 uint64_t forwarded=0;
 while(!stopping){
  QueuedTunPacket packet;
  {std::unique_lock<std::mutex> lock(queueMutex);queueReady.wait(lock,[]{return stopping.load()||queueCount!=0;});if(stopping)break;
   packet=tunQueue[queueHead];queueHead=(queueHead+1)%tunQueue.size();--queueCount;}
  bool sampled=(++forwarded&63)==0;auto began=sampled?std::chrono::steady_clock::now():std::chrono::steady_clock::time_point{};
  bool ok=frame(FromTun,packet.bytes,packet.size);
  if(sampled){auto elapsed=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-began).count());++pipePackets;pipeNanos+=elapsed;auto previous=pipeMaxNanos.load();while(elapsed>previous&&!pipeMaxNanos.compare_exchange_weak(previous,elapsed)){} }
  if(!ok){stopPacketQueue();CancelIoEx(pipe,nullptr);break;}
 }
}
void sendPackets(){
 HANDLE waits[]={readEvent(session),worker};
 while(!stopping){
  ++polls;DWORD size=0;BYTE* p=receivePacket(session,&size);
  if(p){
   ++rawPackets;rawBytes+=size;
   if(size<20)++shortPackets;
   else if(size>Mtu)++oversizedPackets;
   else {
    {std::lock_guard<std::mutex> lock(queueMutex);
     if(queueCount==tunQueue.size())++helperQueueDrops;
     else {auto& packet=tunQueue[queueTail];packet.size=size;memcpy(packet.bytes,p,size);queueTail=(queueTail+1)%tunQueue.size();++queueCount;}}
    queueReady.notify_one();
   }
   releasePacket(session,p);continue;
  }
  DWORD receiveError=GetLastError();
  if(receiveError!=ERROR_NO_MORE_ITEMS){DWORD expected=0;systemError.compare_exchange_strong(expected,receiveError);break;}
  if(WaitForMultipleObjects(2,waits,FALSE,250)==WAIT_OBJECT_0+1)break;
 }
 stopPacketQueue();CancelIoEx(pipe,nullptr);
}
void joinPacketWorkers(std::thread& sender,std::thread& writer){
 stopPacketQueue();
 if(sender.joinable())sender.join();
 if(writer.joinable()){
  // Repeat cancellation to cover a writer that was scheduled just after the
  // first cancel. No new packet can be dequeued after stopPacketQueue.
  while(WaitForSingleObject(writer.native_handle(),50)==WAIT_TIMEOUT)CancelIoEx(pipe,nullptr);
  writer.join();
 }
}
void checkSponsor(DWORD pid,const std::wstring& name){
 const std::wstring prefix=L"\\\\.\\pipe\\ConnectCore-";if(!pid||name.size()!=prefix.size()+64||name.rfind(prefix,0)!=0)throw DWORD(ERROR_INVALID_PARAMETER);for(size_t i=prefix.size();i<name.size();++i)if(!((name[i]>=L'0'&&name[i]<=L'9')||(name[i]>=L'a'&&name[i]<=L'f')))throw DWORD(ERROR_INVALID_PARAMETER);
 worker=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);if(!worker)throw GetLastError();wchar_t path[32768];DWORD n=32768;check(QueryFullProcessImageNameW(worker,0,path,&n)?0:GetLastError());if(_wcsicmp(std::wstring(path,n).c_str(),adjacent(L"connect-desktop-core.exe").c_str()))throw DWORD(ERROR_ACCESS_DENIED);
 for(int i=0;i<200;++i){pipe=CreateFileW(name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION|FILE_FLAG_OVERLAPPED,nullptr);if(pipe!=INVALID_HANDLE_VALUE)break;if(GetLastError()!=ERROR_PIPE_BUSY&&GetLastError()!=ERROR_FILE_NOT_FOUND)throw GetLastError();if(WaitForSingleObject(worker,50)!=WAIT_TIMEOUT)throw DWORD(ERROR_PROCESS_ABORTED);}
 if(pipe==INVALID_HANDLE_VALUE)throw DWORD(ERROR_TIMEOUT);ULONG actual=0;check(GetNamedPipeServerProcessId(pipe,&actual)?0:GetLastError());if(actual!=pid)throw DWORD(ERROR_ACCESS_DENIED);
}
}
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){
 if(!IsUserAnAdmin())return ERROR_ELEVATION_REQUIRED;WSADATA ws;WSAStartup(MAKEWORD(2,2),&ws);int argc=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);std::thread sender,pipeSender;bool explicitStop=false;DWORD error=0;
 HANDLE exclusivity=nullptr;
 try{
  bool standaloneRecovery=argc==2&&std::wstring(argv[1])==L"--recover";
  if(!standaloneRecovery){if(argc!=3)throw DWORD(ERROR_INVALID_PARAMETER);wchar_t* end=nullptr;unsigned long pid=wcstoul(argv[2],&end,10);if(!end||*end||pid>MAXDWORD)throw DWORD(ERROR_INVALID_PARAMETER);checkSponsor(static_cast<DWORD>(pid),argv[1]);}
  exclusivity=CreateMutexW(nullptr,FALSE,L"Global\\ConnectCoreNetworkHelper");if(!exclusivity)throw GetLastError();DWORD acquired=WaitForSingleObject(exclusivity,0);if(acquired!=WAIT_OBJECT_0&&acquired!=WAIT_ABANDONED)throw DWORD(ERROR_BUSY);
  check(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,nullptr,&engine));
  if(standaloneRecovery){recover();if(argv)LocalFree(argv);FwpmEngineClose0(engine);ReleaseMutex(exclusivity);CloseHandle(exclusivity);return 0;}
  BYTE h[8];if(!readExact(h,8)||h[0]!='C'||h[1]!='C'||h[2]!=2)throw DWORD(ERROR_INVALID_DATA);DWORD length;memcpy(&length,h+4,4);if(h[3]==8&&length==0){recover();status(1);if(argv)LocalFree(argv);CloseHandle(pipe);CloseHandle(worker);FwpmEngineClose0(engine);ReleaseMutex(exclusivity);CloseHandle(exclusivity);return 0;}if(h[3]!=Configure)throw DWORD(ERROR_INVALID_DATA);
  FWPM_SUBLAYER0* existing=nullptr;DWORD present=FwpmSubLayerGetByKey0(engine,&Sublayer,&existing);if(present==ERROR_SUCCESS){FwpmFreeMemory0(reinterpret_cast<void**>(&existing));throw DWORD(ERROR_ALREADY_EXISTS);}if(present!=FWP_E_SUBLAYER_NOT_FOUND)throw present;
  Plan p{};if(length!=sizeof(p)||!readExact(&p,sizeof(p)))throw DWORD(ERROR_INVALID_DATA);validate(p);stage=1;trustedDLL();
  stage=2;wchar_t* end=nullptr;DWORD pid=wcstoul(argv[2],&end,10);std::wstring name=L"ccvpn-"+std::to_wstring(pid);NET_LUID old{};if(ConvertInterfaceAliasToLuid(name.c_str(),&old)==ERROR_SUCCESS)throw DWORD(ERROR_ALREADY_EXISTS);check(CoCreateGuid(&adapterGuid));adapter=createAdapter(name.c_str(),L"CONNECT CORE",&adapterGuid);if(!adapter)throw GetLastError();getLuid(adapter,&luid);check(ConvertInterfaceLuidToGuid(&luid,&adapterGuid));session=startSession(adapter,0x400000);if(!session)throw GetLastError();stage=3;checkpoint();stage=5;installGuard(p);configure(p);stage=9;status(3);pipeSender=std::thread(writePackets);sender=std::thread(sendPackets);
  while(!stopping){if(!readExact(h,8))break;if(h[0]!='C'||h[1]!='C'||h[2]!=2)throw DWORD(ERROR_INVALID_DATA);memcpy(&length,h+4,4);if(h[3]==Exit&&length==0){explicitStop=true;break;}if(h[3]!=ToTun||length<20||length>Mtu)throw DWORD(ERROR_INVALID_DATA);BYTE bytes[Mtu];if(!readExact(bytes,length))break;BYTE* packet=allocatePacket(session,length);if(!packet){DWORD e=GetLastError();if(e==ERROR_BUFFER_OVERFLOW){++ringDrops;continue;}throw e;}memcpy(packet,bytes,length);sendPacket(session,packet);}
  joinPacketWorkers(sender,pipeSender);if(explicitStop){uint64_t counters[10]={rawPackets.load(),rawBytes.load(),polls.load(),ringDrops.load(),pipeNanos.load(),pipeMaxNanos.load(),pipePackets.load(),shortPackets.load(),oversizedPackets.load(),helperQueueDrops.load()};frame(35,counters,sizeof(counters));cleanup();status(1);} // EOF/crash intentionally retains persistent protection.
 }catch(DWORD e){error=e;systemError=e;stopPacketQueue();CancelIoEx(pipe,nullptr);joinPacketWorkers(sender,pipeSender);if(guard){status(4,5);}else{closeTun();status(4,5);}}
 closeTun();if(worker)CloseHandle(worker);if(pipe!=INVALID_HANDLE_VALUE)CloseHandle(pipe);if(permitEngine)FwpmEngineClose0(permitEngine);if(engine)FwpmEngineClose0(engine);if(wintun)FreeLibrary(wintun);if(argv)LocalFree(argv);if(exclusivity){ReleaseMutex(exclusivity);CloseHandle(exclusivity);}WSACleanup();return static_cast<int>(error);
}
