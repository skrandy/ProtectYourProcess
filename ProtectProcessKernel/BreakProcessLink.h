#pragma once
//断链隐藏进程
NTSTATUS BreakProcessLink(ULONGLONG pid);

//将进程eprocess加回到链表中
NTSTATUS AddProcessLink(ULONGLONG pid);