#include <ntddk.h>
#include <wdf.h>

DRIVER_INITIALIZE DriverEntry;

#define NTDEVICE_NAME_STRING L"\\Device\\AGENTDRV"
#define SYMBOLIC_NAME_STRING L"\\DosDevices\\agentdrv"
#define PROCESS_EVENT_NAME_STRING L"\\BaseNamedObjects\\EIFProcEvent"

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT self;
	HANDLE processId;
	PKEVENT processEvent;
	HANDLE parentId;
	BOOLEAN create;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _ProcessCallbackInfo {
	HANDLE  parentId;
	HANDLE  processId;
	BOOLEAN create;
} PROCESS_CALLBACK_INFO, *PPROCESS_CALLBACK_INFO;

#define SIZEOF_PROCESS_CALLBACK_INFO sizeof(PROCESS_CALLBACK_INFO)
#define IOCTL_GET_PROCESS_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

PDEVICE_OBJECT g_deviceObject;

VOID ProcessNotifyCallback(HANDLE parentId, HANDLE processId, BOOLEAN create) {
	UNREFERENCED_PARAMETER(create);
	PDEVICE_EXTENSION deviceExtension;
	deviceExtension = g_deviceObject->DeviceExtension;
	deviceExtension->parentId = parentId;
	deviceExtension->processId = processId;
	deviceExtension->create = create;
	KeSetEvent(deviceExtension->processEvent, 0, FALSE);
	KeClearEvent(deviceExtension->processEvent);
	DbgPrint("****Process %u started: parent %u.\n", processId, parentId);
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject) {
	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
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
	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();
	irpStack = IoGetCurrentIrpStackLocation(Irp);
	switch (irpStack->MajorFunction) {
	case IRP_MJ_CREATE:
		status = STATUS_SUCCESS;
		break;
	case IRP_MJ_CLOSE:
		status = STATUS_SUCCESS;
		break;
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	DbgPrint("****Device Control.\n");
	PIO_STACK_LOCATION irpStack;
	PDEVICE_EXTENSION deviceExtension = DeviceObject->DeviceExtension;
	PPROCESS_CALLBACK_INFO processCallbackInfo;
	NTSTATUS status;

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_GET_PROCESS_INFO:
		DbgPrint("****GET_PROCESS_INFO.\n");
		if (irpStack->Parameters.DeviceIoControl.OutputBufferLength >= SIZEOF_PROCESS_CALLBACK_INFO) {
			processCallbackInfo = Irp->AssociatedIrp.SystemBuffer;
			processCallbackInfo->parentId = deviceExtension->parentId;
			processCallbackInfo->processId = deviceExtension->processId;
			processCallbackInfo->create = deviceExtension->create;
			status = STATUS_SUCCESS;
			DbgPrint("****Sending PID: %u.\n", processCallbackInfo->processId);
		}
		break;
	default:
		ASSERT(FALSE);
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	Irp->IoStatus.Status = status;
	if (status == STATUS_SUCCESS)
		Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	else
		Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status;
	PDEVICE_EXTENSION deviceExtension;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString, processEventUnicodeString;
	HANDLE processHandle;
	RtlInitUnicodeString(&deviceNameUnicodeString, NTDEVICE_NAME_STRING);
	status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_deviceObject);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE_CLOSE;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CREATE_CLOSE;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;
	DriverObject->DriverUnload = OnUnload;
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, SYMBOLIC_NAME_STRING);
	status = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(g_deviceObject);
		return status;
	}
	status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(g_deviceObject);
		return status;
	}
	deviceExtension = g_deviceObject->DeviceExtension;
	RtlInitUnicodeString(&processEventUnicodeString, PROCESS_EVENT_NAME_STRING);
	deviceExtension->processEvent = IoCreateNotificationEvent(&processEventUnicodeString, &processHandle);
	KeClearEvent(deviceExtension->processEvent);
	DbgPrint("****Agent driver loaded.\n");
	return status;
}
