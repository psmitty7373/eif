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

const WCHAR deviceNameBuffer[] = L"\\Device\\EIFDRV";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\eifdrv";

PDEVICE_OBJECT eifDevice;

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
	PVOID tempPage = ExAllocatePoolWithTag(NonPagedPool, (128 * 1024 * 1024), 8888);
	resp.success = 1;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	if (tempPage) {
		switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_OPEN_PID:
			_REQUESTMEMORY req;
			PEPROCESS srcProcess;
			PEPROCESS dstProcess;
			KAPC_STATE state;
			NTSTATUS srcSuccess, dstSuccess;
			// convert incoming message to struct
			memcpy(&req, pBuf, sizeof(req));
			// get memory from target process
			srcSuccess = PsLookupProcessByProcessId((HANDLE)req.srcPID, &srcProcess);
			dstSuccess = PsLookupProcessByProcessId((HANDLE)req.dstPID, &dstProcess);
			if (NT_SUCCESS(srcSuccess) && NT_SUCCESS(dstSuccess)) {
				__try {
					KeStackAttachProcess(srcProcess, &state);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					resp.success = 2;
					break;
				}
				__try {
					memcpy(&resp.packet, (void*)req.srcPageAddress, 12);
					memcpy(tempPage, (void*)req.srcPageAddress, req.pageLength);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					resp.success = 3;
				}
				__try {
					KeUnstackDetachProcess(&state);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					resp.success = 4;
					break;
				}
				__try {
					KeStackAttachProcess(dstProcess, &state);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					resp.success = 5;
					break;
				}
				__try {
					memcpy((void*)req.dstPageAddress, tempPage, req.pageLength);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					resp.success = 6;
					break;
				}
				__try {
					KeUnstackDetachProcess(&state);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					resp.success = 7;
				}
			}
			else {
				resp.success = 8;
			}
			break;
		}
	}
	ExFreePoolWithTag(tempPage, 8888);
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
