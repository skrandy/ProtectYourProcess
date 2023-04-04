#include"pch.h"
#include"ProtectProcess.h"
#include"ProtectProcessCommon.h"
#include"AutoLock.h"
#include"BreakProcessLink.h"
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION Info
);//�����ͽ����йصľ��ǰ�Ļص�����
DRIVER_UNLOAD ProcessProtectUnload;
//ж�غ���
DRIVER_DISPATCH ProcessProtectCreateClose;
//�򿪺͹رպ���


NTSTATUS ProcessProtectDeviceIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp);//DeviceIoControl������
//��ӽ���PID
bool AddProcess(ULONG pid);
//ɾ��ָ������PID
bool RemoveProcess(ULONG pid);
//�ҵ�ָ������pid
bool FindProcess(ULONG pid);

//ȫ�ֱ����ṹ��
Globals g_Data;


extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
	KdPrint(("Welcome to ProtectProcess Kernel"));
	//��ʼ��ȫ�ֱ����ṹ��
	g_Data.Init();

	//����һ����ʼ����������ں�������ֵ
	auto status = STATUS_SUCCESS;

	//��ʼ��Ҫ���еĲ���
	OB_OPERATION_REGISTRATION operations[] =
	{
		{
			PsProcessType,//�������ͣ�����������Ǳ������̣����Բ��ý��̵�Type
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,//�Ըö���Ҫ���еĲ��������ﲻ���Ǹ��ƻ��Ǵ����Ƕ�Ҫ
			OnPreOpenProcess,NULL			//Ҫ���õĻص�����,û�о���null
		}
	};

	OB_CALLBACK_REGISTRATION reg = {
		OB_FLT_REGISTRATION_VERSION,//�̶�ֵ
		1,//��Ϊ����ǰ��ֻ��һ������
		RTL_CONSTANT_STRING(L"1231111.111"),//�߶�ֵ�����ֻҪ��֤���ظ��ͺ�,������һ��unicode�ַ���
		NULL,//ϵͳ���ã��������null����
		operations//Ҫ���еĲ����ļ�¼����
	};

	//����豸����ͷ������ӵ�unicodestring�ַ���
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\" PROCESS_PROTECT_NAME);
	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\" PROCESS_PROTECT_NAME);
	PDEVICE_OBJECT DeviceObject = nullptr;

	//����do-while�����Ϊ���ڳ��������ʱ��ֱ��һ��breakֹͣ�����ȽϷ���,��������ֱ�Ӳ���while��
	do
	{
		status = ObRegisterCallbacks(&reg, &g_Data.RegHandle);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		//ע�����֪ͨ

		status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create device object (status=%08X)\n", status));
			break;
		}
		//�����豸����

		status = IoCreateSymbolicLink(&symName, &deviceName);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create symbolic link (status=%08X)\n", status));
			break;
		}
		//������������
	} while (false);

	if (!NT_SUCCESS(status)) {
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
		if (g_Data.RegHandle)
			ObUnRegisterCallbacks(&g_Data.RegHandle);
	}
	//��ǰԤ��������
	DriverObject->DriverUnload = ProcessProtectUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = ProcessProtectCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessProtectCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProcessProtectDeviceIoControl;

	KdPrint((DRIVER_PREFIX "DriverEntry completed successfully\n"));

	return status;
}
void ProcessProtectUnload(PDRIVER_OBJECT DriverObject) {
	//ɨβ����
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
	//�ж��Ƿ����ں˶�������Ǿ�ֱ�ӷ��ز������ˡ�

	auto process = (PEPROCESS)Info->Object;
	//ÿ�����̶���һ�� EPROCESS �ṹ�����汣���Ž��̵ĸ�����Ϣ������ؽṹ��ָ�롣
	auto pid = HandleToULong(PsGetProcessId(process));
	//ͨ��PsGetProcessId��EPROCESSת���ɽ��̵�ID���������þ����ʽ��Ȼ������HandleToULong�������ULONG����ULONG���͵�PID��

	AutoLock<FastMutex> locker(g_Data.Lock);
	//ʹ�ÿ��ٻ����屣֤��ȫ

	if (FindProcess(pid)) {
		//�ڱ����б���������ˣ�����о�ɾ�����Ĺر�Ȩ�ޣ�����ֹ���������¹ر�
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
		//���ﲻ���üӼ���ֻ������� & | ��Щ����������ΪWindows�ڲ�ͨ���궨��Ķ�ֵ������ġ�
	}

	return OB_PREOP_SUCCESS;
}

NTSTATUS ProcessProtectDeviceIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	auto stack = IoGetCurrentIrpStackLocation(pIrp);//��ȡ��ǰ��IOջ
	auto status = STATUS_SUCCESS;
	auto len = 0;

	//���ݲ�ͬ��IO������ʵ�ֲ�ͬ�Ĳ���
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_PROCESS_PROTECT_BY_PID:
	{//���pid�Ĳ�����
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size % sizeof(ULONG) != 0)
		{
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		//�ж������pid�ǲ���ulong���͵ģ���Ϊ���ǲ��õ���ULONG����ֹ���������
		auto data = (ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		//��ȡ���뻺����
		AutoLock<FastMutex> lock(g_Data.Lock);//�Զ���ȡ���ٻ����壬��֤�̰߳�ȫ
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
			//������pidʧ��Ҳ�˳�
			len += sizeof(ULONG);
			//���Ӳ����ֽ���
		}
		break;
	}
	case IOCTL_PROCESS_UNPROTECT_BY_PID:
	{
		//ɾ���������Ľ���
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size % sizeof(ULONG) != 0)
		{
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		//�ж������pid�ǲ���ulong���͵ģ���Ϊ���ǲ��õ���ULONG����ֹ���������
		auto data = (ULONG*)pIrp->AssociatedIrp.SystemBuffer;
		//��ȡ���뻺����
		AutoLock<FastMutex> lock(g_Data.Lock);//�Զ���ȡ���ٻ����壬��֤�̰߳�ȫ

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
		//���㱻�����Ľ���
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
	KdPrint(("����������\n"));
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