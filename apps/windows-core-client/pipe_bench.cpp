#include "pipe_io.h"
#include <thread>
#include <chrono>
#include <algorithm>
#include <cstdio>
#include <stdexcept>

// The baseline is the released 0.2.4 per-operation event and two-write frame.
bool legacy(HANDLE pipe,bool reading,void* bytes,DWORD size){
 auto p=static_cast<BYTE*>(bytes);
 while(size){OVERLAPPED o{};o.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!o.hEvent)return false;
 DWORD n=0;BOOL ok=reading?ReadFile(pipe,p,size,&n,&o):WriteFile(pipe,p,size,&n,&o);
 if(!ok&&GetLastError()==ERROR_IO_PENDING)ok=GetOverlappedResult(pipe,&o,&n,TRUE);
 CloseHandle(o.hEvent);if(!ok||!n)return false;p+=n;size-=n;}return true;
}
double run(bool baseline,int sample){
 wchar_t name[128];swprintf_s(name,L"\\\\.\\pipe\\CONNECT-perf-%lu-%d-%d",GetCurrentProcessId(),baseline,sample);
 HANDLE server=CreateNamedPipeW(name,PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,1,65536,65536,0,nullptr);
 if(server==INVALID_HANDLE_VALUE)throw std::runtime_error("pipe creation failed");
 constexpr uint32_t count=20000;bool received=false;
 auto io=baseline?legacy:connect_pipe::transfer;
 std::thread reader([&]{HANDLE client=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);if(client==INVALID_HANDLE_VALUE)return;
 BYTE h[8],p[1100];received=true;
 for(uint32_t i=0;i<count;i++){DWORD length=0,index=0;if(!io(client,true,h,8)){received=false;break;}memcpy(&length,h+4,4);
 if(h[0]!='C'||h[1]!='C'||h[2]!=2||h[3]!=33||length!=sizeof(p)||!io(client,true,p,sizeof(p))){received=false;break;}
 memcpy(&index,p,4);if(index!=i){received=false;break;}}
 CloseHandle(client);});
 OVERLAPPED connection{};connection.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);DWORD ignored=0;
 BOOL connected=ConnectNamedPipe(server,&connection);DWORD error=GetLastError();
 if(!connected&&error==ERROR_IO_PENDING)connected=GetOverlappedResult(server,&connection,&ignored,TRUE);
 else if(!connected&&error==ERROR_PIPE_CONNECTED)connected=TRUE;
 CloseHandle(connection.hEvent);
 BYTE packet[1100]{};bool sent=connected!=FALSE;
 auto start=std::chrono::steady_clock::now();
 for(uint32_t i=0;sent&&i<count;i++){memcpy(packet,&i,4);
 if(baseline){DWORD length=sizeof(packet);BYTE h[8]={'C','C',2,33};memcpy(h+4,&length,4);sent=legacy(server,false,h,8)&&legacy(server,false,packet,sizeof(packet));}
 else sent=connect_pipe::frame(server,33,packet,sizeof(packet));}
 FlushFileBuffers(server);CloseHandle(server);reader.join();
 double seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
 if(!sent||!received)throw std::runtime_error("packet integrity failed");
 return double(count)*sizeof(packet)*8/seconds/1000000;
}
int main(){try{double before[3],after[3];for(int i=0;i<3;i++){before[i]=run(true,i);after[i]=run(false,i);}std::sort(before,before+3);std::sort(after,after+3);
 printf("{\"scope\":\"Windows overlapped named pipe, not Internet\",\"payload_bytes\":1100,\"packets_per_sample\":20000,\"samples\":3,\"baseline_mbps\":%.3f,\"candidate_mbps\":%.3f,\"ratio\":%.3f,\"integrity\":\"passed\"}\n",before[1],after[1],after[1]/before[1]);return 0;
 }catch(const std::exception& e){fprintf(stderr,"%s\n",e.what());return 1;}}
