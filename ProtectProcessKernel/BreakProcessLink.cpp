#include"pch.h"

ULONG_PTR GetActiveProcessLinksOffset();
VOID UtilBreakLink(PLIST_ENTRY pListEntry);


NTSTATUS BreakProcessLink(ULONGLONG pid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS tempPEprocess = { 0 };
	ULONG_PTR listEntryOffset = 0;
	PLIST_ENTRY tempPListEntry = 0;
	
	status = PsLookupProcessByProcessId((HANDLE)pid, &tempPEprocess);
	
	//函数调用失败，或者EPROCESS为空，或者进程为退出状态
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	if (tempPEprocess == NULL || PsGetProcessExitStatus(tempPEprocess) != 0x103)
	{
		ObDereferenceObject(tempPEprocess);
		return status;
	}
	listEntryOffset = GetActiveProcessLinksOffset();
	if (!listEntryOffset)
	{
		ObDereferenceObject(tempPEprocess);
		status = STATUS_UNSUCCESSFUL;
		return status;
	}
	tempPListEntry = (PLIST_ENTRY)((ULONG_PTR)tempPEprocess + listEntryOffset);
	UtilBreakLink(tempPListEntry);
	ObDereferenceObject(tempPEprocess);
	return status;
}


ULONG_PTR GetUniqueProcessIdOffset()
{
	ULONG_PTR offset = 0;
	HANDLE pid[2];
	PEPROCESS eprocess[2];
	pid[0] = (HANDLE)4;
	pid[1] = PsGetCurrentProcessId();
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid[0], &eprocess[0])))
	{
		return 0;
	}
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid[1], &eprocess[1])))
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

// 利用PID的偏移动态获取 ActiveProcessLinks 相对于 EPROCESS 的偏移
ULONG_PTR GetActiveProcessLinksOffset()
{
	ULONG_PTR PidOffset = GetUniqueProcessIdOffset();
	if (PidOffset == 0) return 0;
	return PidOffset + sizeof(void*);
}

VOID UtilBreakLink(PLIST_ENTRY pListEntry)
{
	PLIST_ENTRY preNode		= { 0 };
	PLIST_ENTRY nextNode	= { 0 };
	
	preNode = pListEntry->Blink;
	nextNode = pListEntry->Flink;

	preNode->Flink = pListEntry->Flink;
	nextNode->Blink = pListEntry->Blink;

	//自己指向自己
	pListEntry->Flink = pListEntry;
	pListEntry->Blink = pListEntry;
}