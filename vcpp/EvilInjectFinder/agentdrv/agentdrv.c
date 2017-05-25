#include <ntddk.h>
#include <wdf.h>

DRIVER_INITIALIZE DriverEntry;
KDEFERRED_ROUTINE CustomTimerDPC;

#define NTDEVICE_NAME_STRING L"\\Device\\AGENTDRV"
#define SYMBOLIC_NAME_STRING L"\\DosDevices\\agentdrv"
#define TAG (ULONG) 'TEVE'

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT  Self;
	LIST_ENTRY      EventQueueHead;
	KSPIN_LOCK      QueueLock;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _REGISTER_EVENT {
	HANDLE  hEvent;
	LARGE_INTEGER DueTime;
} REGISTER_EVENT, *PREGISTER_EVENT;

typedef struct _FILE_CONTEXT {
	IO_REMOVE_LOCK  FileRundownLock;
} FILE_CONTEXT, *PFILE_CONTEXT;

typedef struct _NOTIFY_RECORD {
	LIST_ENTRY      ListEntry;
	union {
		PKEVENT     Event;
		PIRP        PendingIrp;
	} Message;
	KDPC Dpc;
	KTIMER Timer;
	PFILE_OBJECT FileObject;
	PDEVICE_EXTENSION DeviceExtension;
	BOOLEAN CancelRoutineFreeMemory;
} NOTIFY_RECORD, *PNOTIFY_RECORD;

#define SIZEOF_REGISTER_EVENT sizeof(REGISTER_EVENT )
#define IOCTL_REGISTER_EVENT CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS )

typedef struct {
	ULONG srcPID;
	ULONG dstPID;
#ifdef _WIN64
	ULONGLONG srcPageAddress;
	ULONGLONG dstPageAddress;
#else
	ULONG srcPageAddress;
	ULONG dstPageAddress;
#endif
	SIZE_T pageLength;
} _REQUESTMEMORY;

typedef struct {
	BYTE success;
	BYTE packet[25];
} _KernelResponse;

VOID EventCancelRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PDEVICE_EXTENSION   deviceExtension;
	KIRQL               oldIrql;
	PNOTIFY_RECORD      notifyRecord;

	deviceExtension = DeviceObject->DeviceExtension;
	IoReleaseCancelSpinLock(Irp->CancelIrql);
	KeAcquireSpinLock(&deviceExtension->QueueLock, &oldIrql);
	notifyRecord = Irp->Tail.Overlay.DriverContext[3];
	ASSERT(NULL != notifyRecord);
	ASSERT(IRP_BASED == notifyRecord->Type);
	RemoveEntryList(&notifyRecord->ListEntry);
	notifyRecord->Message.PendingIrp = NULL;
	if (KeCancelTimer(&notifyRecord->Timer)) {
		ExFreePoolWithTag(notifyRecord, TAG);
		notifyRecord = NULL;
	}
	else {
		if (notifyRecord->CancelRoutineFreeMemory == FALSE) {
			InitializeListHead(&notifyRecord->ListEntry);
		}
		else {
			ExFreePoolWithTag(notifyRecord, TAG);
			notifyRecord = NULL;
		}
	}
	KeReleaseSpinLock(&deviceExtension->QueueLock, oldIrql);
	Irp->Tail.Overlay.DriverContext[3] = NULL;
	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return;
}

VOID CustomTimerDPC(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	PNOTIFY_RECORD notifyRecord = DeferredContext;
	PDEVICE_EXTENSION deviceExtension;
	PIRP irp;
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ASSERT(notifyRecord != NULL); // can't be NULL
	_Analysis_assume_(notifyRecord != NULL);
	deviceExtension = notifyRecord->DeviceExtension;
	KeAcquireSpinLockAtDpcLevel(&deviceExtension->QueueLock);
	RemoveEntryList(&notifyRecord->ListEntry);
	irp = notifyRecord->Message.PendingIrp;
	if (irp != NULL) {
		if (IoSetCancelRoutine(irp, NULL) != NULL) {
			irp->Tail.Overlay.DriverContext[3] = NULL;
			KeReleaseSpinLockFromDpcLevel(&deviceExtension->QueueLock);
			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			KeAcquireSpinLockAtDpcLevel(&deviceExtension->QueueLock);
		}
		else {
			InitializeListHead(&notifyRecord->ListEntry);
			notifyRecord->CancelRoutineFreeMemory = TRUE;
			notifyRecord = NULL;
		}
	}
	else {
		ASSERT(notifyRecord->CancelRoutineFreeMemory == FALSE);
	}
	KeReleaseSpinLockFromDpcLevel(&deviceExtension->QueueLock);
	if (notifyRecord != NULL) {
		ExFreePoolWithTag(notifyRecord, TAG);
		notifyRecord = NULL;
	}
	return;
}

NTSTATUS RegisterIrpBasedNotification(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PDEVICE_EXTENSION   deviceExtension;
	PNOTIFY_RECORD notifyRecord;
	PIO_STACK_LOCATION irpStack;
	KIRQL   oldIrql;
	PREGISTER_EVENT registerEvent;

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	deviceExtension = DeviceObject->DeviceExtension;
	registerEvent = (PREGISTER_EVENT)Irp->AssociatedIrp.SystemBuffer;
	notifyRecord = ExAllocatePoolWithQuotaTag(NonPagedPool,	sizeof(NOTIFY_RECORD), TAG);
	if (NULL == notifyRecord) {
		return  STATUS_INSUFFICIENT_RESOURCES;
	}
	InitializeListHead(&notifyRecord->ListEntry);
	notifyRecord->FileObject = irpStack->FileObject;
	notifyRecord->DeviceExtension = deviceExtension;
	notifyRecord->Message.PendingIrp = Irp;
	if (registerEvent->DueTime.QuadPart > 0) {
		registerEvent->DueTime.QuadPart = -(registerEvent->DueTime.QuadPart);
	}
	KeInitializeDpc(&notifyRecord->Dpc, CustomTimerDPC, notifyRecord);
	//KeInitializeTimer(&notifyRecord->Timer);
	KeAcquireSpinLock(&deviceExtension->QueueLock, &oldIrql);
	IoSetCancelRoutine(Irp, EventCancelRoutine);
	if (Irp->Cancel) {
		if (IoSetCancelRoutine(Irp, NULL) != NULL) {
			KeReleaseSpinLock(&deviceExtension->QueueLock, oldIrql);
			ExFreePoolWithTag(notifyRecord, TAG);
			return STATUS_CANCELLED;
		}
		else {
		}
	}
	IoMarkIrpPending(Irp);
	InsertTailList(&deviceExtension->EventQueueHead, &notifyRecord->ListEntry);
	notifyRecord->CancelRoutineFreeMemory = FALSE;
	Irp->Tail.Overlay.DriverContext[3] = notifyRecord;
	//KeSetTimer(&notifyRecord->Timer, registerEvent->DueTime, &notifyRecord->Dpc);
	KeReleaseSpinLock(&deviceExtension->QueueLock, oldIrql);
	return STATUS_PENDING;
}

VOID ProcessNotifyCallback(HANDLE parentPid, HANDLE pid, BOOLEAN create) {
	UNREFERENCED_PARAMETER(create);
	DbgPrint("****Process %u started: parent %u.\n", pid, parentPid);

	PIO_STACK_LOCATION irpStack;
	NTSTATUS status;
	KIRQL oldIrql;
	PLIST_ENTRY thisEntry, nextEntry, listHead;
	PNOTIFY_RECORD notifyRecord;
	PDEVICE_EXTENSION deviceExtension;
	LIST_ENTRY cleanupList;
	PFILE_CONTEXT fileContext;

	deviceExtension = DeviceObject->DeviceExtension;
	irpStack = IoGetCurrentIrpStackLocation(Irp);
	fileContext = irpStack->FileObject->FsContext;
	status = IoAcquireRemoveLock(&fileContext->FileRundownLock, Irp);
	IoReleaseRemoveLockAndWait(&fileContext->FileRundownLock, Irp);
	InitializeListHead(&cleanupList);
	KeAcquireSpinLock(&deviceExtension->QueueLock, &oldIrql);
	listHead = &deviceExtension->EventQueueHead;

	while (!IsListEmpty(&cleanupList))
	{
		PIRP pendingIrp;
		thisEntry = RemoveHeadList(&cleanupList);
		pendingIrp = CONTAINING_RECORD(thisEntry, IRP, Tail.Overlay.ListEntry);
		pendingIrp->Tail.Overlay.DriverContext[3] = NULL;
		pendingIrp->IoStatus.Information = 0;
		pendingIrp->IoStatus.Status = STATUS_CANCELLED;
		IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
	}

}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject) {
	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
	//PDEVICE_EXTENSION deviceExtension = deviceObject->DeviceExtension;
	UNICODE_STRING symLink;
	PAGED_CODE();
	PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
	RtlInitUnicodeString(&symLink, SYMBOLIC_NAME_STRING);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(deviceObject);
	DbgPrint("****Agent driver unloaded.\n");
	return;
}

NTSTATUS Function_IRP_MJ_CREATE_CLOSE(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	DbgPrint("****Agent MG_CREATE_CLOSE.\n");
	PIO_STACK_LOCATION irpStack;
	NTSTATUS status;
	PFILE_CONTEXT fileContext;
	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();
	irpStack = IoGetCurrentIrpStackLocation(Irp);
	switch (irpStack->MajorFunction) {
	case IRP_MJ_CREATE:
		fileContext = ExAllocatePoolWithQuotaTag(NonPagedPool, sizeof(FILE_CONTEXT), TAG);
		if (fileContext == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		IoInitializeRemoveLock(&fileContext->FileRundownLock, TAG, 0, 0);
		irpStack->FileObject->FsContext = (PVOID)fileContext;
		status = STATUS_SUCCESS;
		break;
	case IRP_MJ_CLOSE:
		fileContext = irpStack->FileObject->FsContext;
		ExFreePoolWithTag(fileContext, TAG);
		status = STATUS_SUCCESS;
		break;
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_MJ_CLEANUP(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	DbgPrint("****Agent MG_CREATE_CLEANUP.\n");
	PIO_STACK_LOCATION irpStack;
	NTSTATUS status;
	KIRQL oldIrql;
	PLIST_ENTRY thisEntry, nextEntry, listHead;
	PNOTIFY_RECORD notifyRecord;
	PDEVICE_EXTENSION deviceExtension;
	LIST_ENTRY cleanupList;
	PFILE_CONTEXT fileContext;

	deviceExtension = DeviceObject->DeviceExtension;
	irpStack = IoGetCurrentIrpStackLocation(Irp);
	fileContext = irpStack->FileObject->FsContext;
	status = IoAcquireRemoveLock(&fileContext->FileRundownLock, Irp);
	IoReleaseRemoveLockAndWait(&fileContext->FileRundownLock, Irp);
	InitializeListHead(&cleanupList);
	KeAcquireSpinLock(&deviceExtension->QueueLock, &oldIrql);
	listHead = &deviceExtension->EventQueueHead;
	for (thisEntry = listHead->Flink; thisEntry != listHead; thisEntry = nextEntry)
	{
		nextEntry = thisEntry->Flink;
		notifyRecord = CONTAINING_RECORD(thisEntry, NOTIFY_RECORD, ListEntry);
		if (irpStack->FileObject == notifyRecord->FileObject) {
			if (KeCancelTimer(&notifyRecord->Timer)) {
				RemoveEntryList(thisEntry);
				if (IoSetCancelRoutine(notifyRecord->Message.PendingIrp, NULL) != NULL) {
					InsertTailList(&cleanupList,
						&notifyRecord->Message.PendingIrp->Tail.Overlay.ListEntry);
					ExFreePoolWithTag(notifyRecord, TAG);

				}
				else {
					InitializeListHead(&notifyRecord->ListEntry);
					notifyRecord->CancelRoutineFreeMemory = TRUE;
				}
			}
		}
	}
	KeReleaseSpinLock(&deviceExtension->QueueLock, oldIrql);
	while (!IsListEmpty(&cleanupList))
	{
		PIRP pendingIrp;
		thisEntry = RemoveHeadList(&cleanupList);
		pendingIrp = CONTAINING_RECORD(thisEntry, IRP, Tail.Overlay.ListEntry);
		pendingIrp->Tail.Overlay.DriverContext[3] = NULL;
		pendingIrp->IoStatus.Information = 0;
		pendingIrp->IoStatus.Status = STATUS_CANCELLED;
		IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
	}
	Irp->IoStatus.Status = status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	DbgPrint("****Device Control.\n");
	PIO_STACK_LOCATION irpStack;
	PREGISTER_EVENT registerEvent;
	NTSTATUS status;
	PFILE_CONTEXT fileContext;

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	fileContext = irpStack->FileObject->FsContext;
	status = IoAcquireRemoveLock(&fileContext->FileRundownLock, Irp);
	if (!NT_SUCCESS(status)) {
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}
	switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_REGISTER_EVENT:
		if (irpStack->Parameters.DeviceIoControl.InputBufferLength < SIZEOF_REGISTER_EVENT) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		registerEvent = (PREGISTER_EVENT)Irp->AssociatedIrp.SystemBuffer;
		status = RegisterIrpBasedNotification(DeviceObject, Irp);
		break;
	default:
		ASSERT(FALSE);
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	if (status != STATUS_PENDING) {
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}
	IoReleaseRemoveLock(&fileContext->FileRundownLock, Irp);
	return status;

	/*

	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	BYTE msgBuffer[sizeof(_KernelResponse)] = { 0 };
	_KernelResponse resp;
	resp.success = 1;
	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_OPEN_PID:
		break;
	}
	memcpy(msgBuffer, &resp, sizeof(resp));
	RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
	RtlCopyMemory(pBuf, msgBuffer, sizeof(resp));
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(resp);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;*/
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status;
	PDEVICE_OBJECT deviceObject;
	PDEVICE_EXTENSION deviceExtension;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;
	RtlInitUnicodeString(&deviceNameUnicodeString, NTDEVICE_NAME_STRING);
	status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE_CLOSE;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CREATE_CLOSE;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = Function_IRP_MJ_CLEANUP;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;
	DriverObject->DriverUnload = OnUnload;
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, SYMBOLIC_NAME_STRING);
	status = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(deviceObject);
		return status;
	}
	status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(deviceObject);
		return status;
	}
	deviceExtension = deviceObject->DeviceExtension;
	InitializeListHead(&deviceExtension->EventQueueHead);
	KeInitializeSpinLock(&deviceExtension->QueueLock);
	deviceExtension->Self = deviceObject;
	deviceObject->Flags |= DO_BUFFERED_IO;
	DbgPrint("****Agent driver loaded.\n");
	return status;
}
