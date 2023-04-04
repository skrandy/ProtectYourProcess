#define DRIVER_PREFIX "ProcessProtect"
#define PROCESS_TERMINATE	1
#include"FastMutex.h"
const int MaxPids = 256;//最多的保护进程的数量

//一个全局的结构体
struct Globals {
	int PidsCount;	//当前保护的进程数量
	ULONG Pids[MaxPids];//保护进程的进程id数组
	FastMutex Lock;		//使用快速互斥体来保证线程安全
	PVOID RegHandle;	//为了ObRegisterCallbacks	API的第二个参数，这个参数就是用来唯一标识对象的没啥作用
	void Init()
	{
		Lock.Init();	//初始化快速互斥体，这里不用AutoLock是为了手动来处理，因为这个是会作为一个全局一直存在的。
		memset(Pids, 0x0, MaxPids);
	}
};