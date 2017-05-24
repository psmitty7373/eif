#include <ntddk.h>
#include <wdf.h>

typedef struct _KAPC_STATE
{
	LIST_ENTRY  ApcListHead[2];
	PVOID       Process;
	BOOLEAN     KernelApcInProgress;
	BOOLEAN     KernelApcPending;
	BOOLEAN     UserApcPending;
} KAPC_STATE, *PKAPC_STATE;

extern NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
extern VOID KeStackAttachProcess(PEPROCESS Process, KAPC_STATE *ApcState);
extern VOID KeUnstackDetachProcess(KAPC_STATE *ApcState);
extern NTKERNELAPI VOID KeAttachProcess(PEPROCESS Process);
extern NTKERNELAPI VOID KeDetachProcess();

DRIVER_INITIALIZE DriverEntry;

#define SIOCTL_TYPE 40000
#define IOCTL_HELLO CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_OPEN_PID CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

typedef ULONG(NTAPI *ZWREADVIRTUALMEMORY)(HANDLE, PVOID, PVOID, ULONG, PULONG);

const WCHAR deviceNameBuffer[] = L"\\Device\\AGENTDRV";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\agentdrv";

PDEVICE_OBJECT eifDevice;

void ProcessNotifyCallback() {

}

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

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink;
	//NTSTATUS status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
	RtlInitUnicodeString(&symLink, deviceSymLinkBuffer);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS Function_IRP_MJ_CREATE(PDEVICE_OBJECT DriverObject, PIRP Irp)
{
	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_MJ_CLOSE(PDEVICE_OBJECT DriverObject, PIRP Irp)
{
	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT DriverObject, PIRP Irp)
{
	PIO_STACK_LOCATION pIoStackLocation;
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	BYTE msgBuffer[sizeof(_KernelResponse)] = { 0 };
	_KernelResponse resp;
	resp.success = 1;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_OPEN_PID:
		break;
	}

	//NTSTATUS status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);


	memcpy(msgBuffer, &resp, sizeof(resp));
	RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
	RtlCopyMemory(pBuf, msgBuffer, sizeof(resp));
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(resp);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;
	RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, deviceSymLinkBuffer);
	status = IoCreateDevice(DriverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_UNKNOWN, FALSE, &eifDevice);
	status = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	DriverObject->DriverUnload = OnUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;
	return status;
}
