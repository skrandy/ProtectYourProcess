#define DRIVER_PREFIX "ProcessProtect"
#define PROCESS_TERMINATE	1
#include"FastMutex.h"
const int MaxPids = 256;//���ı������̵�����

//һ��ȫ�ֵĽṹ��
struct Globals {
	int PidsCount;	//��ǰ�����Ľ�������
	ULONG Pids[MaxPids];//�������̵Ľ���id����
	FastMutex Lock;		//ʹ�ÿ��ٻ���������֤�̰߳�ȫ
	PVOID RegHandle;	//Ϊ��ObRegisterCallbacks	API�ĵڶ������������������������Ψһ��ʶ�����ûɶ����
	void Init()
	{
		Lock.Init();	//��ʼ�����ٻ����壬���ﲻ��AutoLock��Ϊ���ֶ���������Ϊ����ǻ���Ϊһ��ȫ��һֱ���ڵġ�
		memset(Pids, 0x0, MaxPids);
	}
};