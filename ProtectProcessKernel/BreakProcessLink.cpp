#include"pch.h"

ULONG_PTR GetActiveProcessLinksOffset();
NTSTATUS UtilBreakPorcessLink(PLIST_ENTRY pListEntry);
NTSTATUS GetProcessListEntry(__in PEPROCESS pEprocess, __out PLIST_ENTRY* ppListEntry);
NTSTATUS GetEProcessByPid(__in HANDLE pid, __out PEPROCESS* pEprocess);
NTSTATUS AddProcessLinkEx(PLIST_ENTRY pListEntry);


NTSTATUS BreakProcessLink(ULONGLONG pid)
{
	NTSTATUS	status = STATUS_UNSUCCESSFUL;
	PEPROCESS	tempPEprocess = { 0 };
	PLIST_ENTRY tempPListEntry = 0;
	status = GetEProcessByPid((HANDLE)pid, &tempPEprocess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = GetProcessListEntry(tempPEprocess, &tempPListEntry);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(tempPEprocess);
		return status;
	}
	status = UtilBreakPorcessLink(tempPListEntry);
	ObDereferenceObject(tempPEprocess);
	return status;
}


//�����̽ṹ����ӻؽ�������
NTSTATUS AddProcessLink(ULONGLONG pid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS tempPEprocess = { 0 };
	PLIST_ENTRY tempPListEntry = 0;

	status = GetEProcessByPid((HANDLE)pid, &tempPEprocess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = GetProcessListEntry(tempPEprocess, &tempPListEntry);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(tempPEprocess);
		return status;
	}
	status = AddProcessLinkEx(tempPListEntry);
	ObDereferenceObject(tempPEprocess);
	return status;
}

NTSTATUS GetProcessListEntry(__in PEPROCESS pEprocess, __out PLIST_ENTRY* ppListEntry)
{
	ULONG_PTR	listEntryOffset = 0;
	NTSTATUS	status = STATUS_SUCCESS;
	PLIST_ENTRY tempPListEntry = NULL;

	listEntryOffset = GetActiveProcessLinksOffset();
	if (!listEntryOffset)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}
	tempPListEntry = (PLIST_ENTRY)((ULONG_PTR)pEprocess + listEntryOffset);
	*ppListEntry = tempPListEntry;
	tempPListEntry = NULL;
	return status;
}
ULONG_PTR GetUniqueProcessIdOffset()
{
	ULONG_PTR offset = 0;
	HANDLE pid[2];
	PEPROCESS eprocess[2];
	pid[0] = (HANDLE)4;
	pid[1] = PsGetCurrentProcessId();
	if (!NT_SUCCESS(GetEProcessByPid(pid[0], &eprocess[0])))
	{
		return 0;
	}
	if (!NT_SUCCESS(GetEProcessByPid(pid[1], &eprocess[1])))
	{
		return 0;
	}
	for (ULONG_PTR i = 0; i < 0x300; i++)
	{
		if (*(PHANDLE)((PUCHAR)eprocess[0] + i) == pid[0] && \
			* (PHANDLE)((PUCHAR)eprocess[1] + i) == pid[1])
		{
			offset = i;
			break;
		}
	}
	ObDereferenceObject(eprocess[0]);
	ObDereferenceObject(eprocess[1]);
	return offset;
}

// ����PID��ƫ�ƶ�̬��ȡ ActiveProcessLinks ����� EPROCESS ��ƫ��
ULONG_PTR GetActiveProcessLinksOffset()
{
	ULONG_PTR PidOffset = GetUniqueProcessIdOffset();
	if (PidOffset == 0) return 0;
	return PidOffset + sizeof(void*);
}

NTSTATUS UtilBreakPorcessLink(PLIST_ENTRY pListEntry)
{
	PLIST_ENTRY preNode = { 0 };
	PLIST_ENTRY nextNode = { 0 };
	NTSTATUS    status = STATUS_SUCCESS;

	preNode = pListEntry->Blink;
	nextNode = pListEntry->Flink;
	if (!preNode || !nextNode)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}
	preNode->Flink = pListEntry->Flink;
	nextNode->Blink = pListEntry->Blink;

	//�Լ�ָ���Լ�
	pListEntry->Flink = pListEntry;
	pListEntry->Blink = pListEntry;
	return status;
}

//1��2�����������
NTSTATUS UtilAddProcessLink(PLIST_ENTRY pPluginListEntry, PLIST_ENTRY pAimListEntry)
{
	PLIST_ENTRY preNode = { 0 };
	NTSTATUS    status = STATUS_SUCCESS;

	if (!pPluginListEntry)
		return STATUS_INVALID_PARAMETER_1;
	if (!pAimListEntry)
		return STATUS_INVALID_PARAMETER_2;
	preNode = pAimListEntry->Blink;
	if (!preNode || preNode == pAimListEntry)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}
	preNode->Flink = pPluginListEntry;
	pPluginListEntry->Blink = preNode;
	pPluginListEntry->Flink = pAimListEntry;
	pAimListEntry->Blink = pPluginListEntry;
	return status;
}

NTSTATUS AddProcessLinkEx(PLIST_ENTRY pListEntry)
{
	HANDLE		aimProcessPid = (HANDLE)0x4;
	NTSTATUS	status = NULL;
	PEPROCESS   tempPEprocess = NULL;
	PLIST_ENTRY pAimProcessListEntry = NULL;

	status = GetEProcessByPid(aimProcessPid, &tempPEprocess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = GetProcessListEntry(tempPEprocess, &pAimProcessListEntry);
	if (!NT_SUCCESS(status))
	{
		ObReferenceObject(tempPEprocess);
		return status;
	}
	status = UtilAddProcessLink(pListEntry, pAimProcessListEntry);
	ObReferenceObject(tempPEprocess);
	return status;
}

NTSTATUS GetEProcessByPid(__in HANDLE pid, __out PEPROCESS* pEprocess)
{
	NTSTATUS	status = STATUS_UNSUCCESSFUL;
	PEPROCESS	tempPEprocess = NULL;

	status = PsLookupProcessByProcessId(pid, &tempPEprocess);
	//��������ʧ�ܣ�����EPROCESSΪ�գ����߽���Ϊ�˳�״̬
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	if (tempPEprocess == NULL || PsGetProcessExitStatus(tempPEprocess) != 0x103)
	{
		ObDereferenceObject(tempPEprocess);
		return status;
	}
	*pEprocess = tempPEprocess;
	tempPEprocess = NULL;
	return status;
}