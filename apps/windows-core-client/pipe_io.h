#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
namespace connect_pipe {
// Separate reader/writer threads keep separate completion events. Reuse begins
// only after GetOverlappedResult completes; no OVERLAPPED operation is reused.
inline bool transfer(HANDLE pipe,bool reading,void* bytes,DWORD size){
 struct Completion {HANDLE event=CreateEventW(nullptr,TRUE,FALSE,nullptr);~Completion(){if(event)CloseHandle(event);}};
 thread_local Completion completion;
 if(!completion.event)return false;
 auto p=static_cast<BYTE*>(bytes);
 while(size){
  ResetEvent(completion.event);OVERLAPPED operation{};operation.hEvent=completion.event;
  // For FILE_FLAG_OVERLAPPED, obtain the byte count from the completion result
  // even when ReadFile/WriteFile completes immediately (Microsoft fileapi contract).
  BOOL ok=reading?ReadFile(pipe,p,size,nullptr,&operation):WriteFile(pipe,p,size,nullptr,&operation);
  if(!ok&&GetLastError()!=ERROR_IO_PENDING)return false;
  DWORD count=0;
  if(!GetOverlappedResult(pipe,&operation,&count,TRUE))return false;
  if(!count){SetLastError(ERROR_BROKEN_PIPE);return false;}p+=count;size-=count;
 }
 return true;
}
inline bool frame(HANDLE pipe,uint8_t kind,const void* payload,DWORD size){
 if(size>1100)return false;
 BYTE bytes[1108]={'C','C',2,kind};memcpy(bytes+4,&size,4);
 if(size)memcpy(bytes+8,payload,size);
 return transfer(pipe,false,bytes,size+8);
}
}
