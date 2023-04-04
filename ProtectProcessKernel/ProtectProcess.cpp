#include"pch.h"
#include"ProtectProcess.h"
#include"ProtectProcessCommon.h"
#include"AutoLock.h"
#include"BreakProcessLink.h"
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION Info
);//操作和进程有关的句柄前的回调函数
DRIVER_UNLOAD ProcessProtectUnload;
//卸载函数
DRIVER_DISPATCH ProcessProtectCreateClose;
//打开和关闭函数


NTSTATUS ProcessProtectDeviceIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp);//DeviceIoControl处理函数
//添加进程PID
bool AddProcess(ULONG pid);
//删除指定进程PID
bool RemoveProcess(ULONG pid);
//找到指定进程pid
bool FindProcess(ULONG pid);

//全局变量结构体
Globals g_Data;


extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
	KdPrint(("Welcome to ProtectProcess Kernel"));
	//初始化全局变量结构体
	g_Data.Init();

	//定义一个初始化的驱动入口函数返回值
	auto status = STATUS_SUCCESS;

	//初始化要进行的操作
	OB_OPERATION_REGISTRATION operations[] =
	{
		{
			PsProcessType,//对象类型，这里的我们是保护进程，所以采用进程的Type
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,//对该对象要进行的操作，这里不管是复制还是打开我们都要
			OnPreOpenProcess,NULL			//要调用的回调函数,没有就填null
		}
	};

	OB_CALLBACK_REGISTRATION reg = {
		OB_FLT_REGISTRATION_VERSION,//固定值
		1,//因为我们前面只有一个操作
		RTL_CONSTANT_STRING(L"1231111.111"),//高度值，这个只要保证不重复就好,这里是一个unicode字符串
		NULL,//系统设置，这个传个null就行
		operations//要进行的操作的记录数组
	};

	//添加设备对象和符号链接的unicodestring字符串
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\" PROCESS_PROTECT_NAME);
	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\" PROCESS_PROTECT_NAME);
	PDEVICE_OBJECT DeviceObject = nullptr;

	//采用do-while语句是为了在出现问题的时候直接一个break停止掉，比较方便,所以这里直接不加while了
	do
	{
		status = ObRegisterCallbacks(&reg, &g_Data.RegHandle);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		//注册对象通知

		status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create device object (status=%08X)\n", status));
			break;
		}
		//创建设备对象

		status = IoCreateSymbolicLink(&symName, &deviceName);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create symbolic link (status=%08X)\n", status));
			break;
		}
		//创建符号链接
	} while (false);

	if (!NT_SUCCESS(status)) {
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
		if (g_Data.RegHandle)
			ObUnRegisterCallbacks(&g_Data.RegHandle);
	}
	//提前预防出问题
	DriverObject->DriverUnload = ProcessProtectUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = ProcessProtectCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessProtectCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProcessProtectDeviceIoControl;

	KdPrint((DRIVER_PREFIX "DriverEntry completed successfully\n"));

	return status;
}
void ProcessProtectUnload(PDRIVER_OBJECT DriverObject) {
	//扫尾工作
	ObUnRegisterCallbacks(g_Data.RegHandle);

	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\" PROCESS_PROTECT_NAME);
	IoDeleteSymbolicLink(&symName);
	IoDeleteDevice(DriverObject->DeviceObject);
}


OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (Info->KernelHandle)
		return OB_PREOP_SUCCESS;
	//判断是否是内核对象，如果是就直接返回不处理了。

	auto process = (PEPROCESS)Info->Object;
	//每个进程都有一个 EPROCESS 结构，里面保存着进程的各种信息，和相关结构的指针。
	auto pid = HandleToULong(PsGetProcessId(process));
	//通过PsGetProcessId把EPROCESS转换成进程的ID，但是是用句柄形式，然后再用HandleToULong把它变成ULONG就是ULONG类型的PID了

	AutoLock<FastMutex> locker(g_Data.Lock);
	//使用快速互斥体保证安全

	if (FindProcess(pid)) {
		//在保护列表里面查找了，如果有就删除它的关闭权限，来防止保护进程呗关闭
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
		//这里不能用加减，只能用这个 & | 这些来操作，因为Windows内部通过宏定义的定值来区别的。
	}

	return OB_PREOP_SUCCESS;
}

NTSTATUS ProcessProtectDeviceIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	auto stack = IoGetCurrentIrpStackLocation(pIrp);//获取当前的IO栈
	auto status = STATUS_SUCCESS;
	auto len = 0;

	//根据不同的IO操作码实现不同的操作
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_PROCESS_PROTECT_BY_PID:
	{//添加pid的操作码
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size % sizeof(ULONG) != 0)
		{
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		//判断输入的pid是不是ulong类型的，因为我们采用的是ULONG，防止溢出的问题
		auto data = (ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		//获取输入缓冲区
		AutoLock<FastMutex> lock(g_Data.Lock);//自动获取快速互斥体，保证线程安全
		for (ULONG i = 0; i < size / sizeof(ULONG); i++)
		{
			auto pid = data[i];
			if (pid == 0)
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (FindProcess(pid))
				continue;
			if (g_Data.PidsCount == MaxPids)
			{
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}
			if (!AddProcess(data[i]))
			{
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			//如果添加pid失败也退出
			len += sizeof(ULONG);
			//增加操作字节数
		}
		break;
	}
	case IOCTL_PROCESS_UNPROTECT_BY_PID:
	{
		//删除被保护的进程
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size % sizeof(ULONG) != 0)
		{
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		//判断输入的pid是不是ulong类型的，因为我们采用的是ULONG，防止溢出的问题
		auto data = (ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		//获取输入缓冲区
		AutoLock<FastMutex> lock(g_Data.Lock);//自动获取快速互斥体，保证线程安全

		for (ULONG i = 0; i < size / sizeof(ULONG); i++)
		{
			if (g_Data.PidsCount == 0)
				break;
			auto pid = data[i];
			if (pid == 0)
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (!RemoveProcess(pid))
				continue;
			len += sizeof(ULONG);
		}
		break;
	}
	case IOCTL_PROCESS_PROTECT_CLEAR:
	{
		//清零被保护的进程
		AutoLock<FastMutex> lock(g_Data.Lock);
		for (int i = 0; i < MaxPids; i++)
		{
			if (g_Data.PidsCount <= 0)
				break;
			if (g_Data.Pids[i] == 0)
				continue;
			status = AddProcessLink(g_Data.Pids[i]);
			if (!NT_SUCCESS(status))
				continue;
			g_Data.Pids[i] = 0;
			g_Data.PidsCount--;
		}
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = len;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

bool AddProcess(ULONG pid)
{
	for (int i = 0; i < MaxPids; i++)
	{
		if (g_Data.Pids[i] == 0)
		{
			g_Data.Pids[i] = pid;
			g_Data.PidsCount++;
			BreakProcessLink(pid);
			return true;
		}
	}
	KdPrint(("进程数已满\n"));
	return false;
}

bool RemoveProcess(ULONG pid)
{
	for (int i = 0; i < MaxPids; i++)
	{
		if (g_Data.Pids[i] == pid)
		{
			AddProcessLink(pid);
			g_Data.Pids[i] = 0;
			g_Data.PidsCount--;
			return true;
		}
	}
	return false;
}

bool FindProcess(ULONG pid)
{
	for (int i = 0; i < MaxPids; i++)
	{
		if (g_Data.Pids[i] == pid)
		{
			return true;
		}
	}
	return false;
}

NTSTATUS ProcessProtectCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}