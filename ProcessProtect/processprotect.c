#include <ntifs.h>
#include "ProcessInformation.h"



#define DEVICE_NAME L"\\device\\ProcessProtect"
#define LINK_NAME L"\\dosdevices\\ProcessProtect"


#define IOCTRL_BASE 0x800

#define MYIOCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_START MYIOCTRL_CODE(0)
#define CTL_PRINT MYIOCTRL_CODE(1)
#define CTL_BYE MYIOCTRL_CODE(2)





typedef struct _SAVE_STRUCT
{
	unsigned int g_save_pid;
	WCHAR str[50];
}SAVE_STRUCT, * PSAVE_STRUCT;

SAVE_STRUCT g_save = { 0 };

PVOID pRegistrationHandle;
//���̹�������ϸ�����������
#define PROCESS_TERMINATE_0       0x1001
//taskkillָ���������
#define PROCESS_TERMINATE_1       0x0001 
//taskkillָ���/f����ǿɱ���̽�����
#define PROCESS_KILL_F			  0x1401
//���̹�������������
#define PROCESS_TERMINATE_2       0x1041
// _LDR_DATA_TABLE_ENTRY ,ע��32λ��64λ�Ķ����С
#ifdef _WIN64
typedef struct _LDR_DATA
{
	LIST_ENTRY listEntry;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING path;
	UNICODE_STRING name;
	ULONG   Flags;
}LDR_DATA, * PLDR_DATA;
#else
typedef struct _LDR_DATA
{
	LIST_ENTRY listEntry;
	ULONG unknown1;
	ULONG unknown2;
	ULONG unknown3;
	ULONG unknown4;
	ULONG unknown5;
	ULONG unknown6;
	ULONG unknown7;
	UNICODE_STRING path;
	UNICODE_STRING name;
	ULONG   Flags;
}LDR_DATA, * PLDR_DATA;
#endif


typedef   enum   _SHUTDOWN_ACTION {
	ShutdownNoReboot,         //�ػ�������
	ShutdownReboot,             //�ػ�������
	ShutdownPowerOff          //�ػ����رյ�Դ
}SHUTDOWN_ACTION;


NTSTATUS NTAPI NtShutdownSystem(IN SHUTDOWN_ACTION Action);


EXTERN_C NTSTATUS LogpSleep(_In_ LONG Millisecond) {
	PAGED_CODE();
	LARGE_INTEGER interval = { 0 };
	interval.QuadPart = -(10000 * Millisecond);  // msec
	return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}



#if DBG
EXTERN_C void AsmInt3();
#endif



NTSTATUS EnumSystemProcess(IN PWCH TargetProcessName);

PUCHAR NTAPI PsGetProcessImageFileName(__in PEPROCESS Process);

NTSTATUS InitTargetProcessNameR(IN PSAVE_STRUCT SaveBuff);


NTSTATUS NTAPI NtQueryInformationProcess(_In_ HANDLE 	ProcessHandle,
	_In_ PROCESSINFOCLASS 	ProcessInformationClass,
	_Out_ PVOID 	ProcessInformation,
	_In_ ULONG 	ProcessInformationLength,
	_Out_opt_ PULONG 	ReturnLength
);



VOID IsFun();
VOID IsProcessActive();



OB_PREOP_CALLBACK_STATUS PreProcessHandle(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{

	UNREFERENCED_PARAMETER(RegistrationContext);
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);

	if (pid!=0 && pid == g_save.g_save_pid)
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)//������ֹ
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)//openprocess
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)//�ڴ��
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)//�ڴ�д
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}
	return OB_PREOP_SUCCESS;

}


VOID CallBackRegedit(PDRIVER_OBJECT pDriver)
{

	OB_OPERATION_REGISTRATION oor;
	OB_CALLBACK_REGISTRATION ocr;
	PLDR_DATA pld;//ָ��_LDR_DATA_TABLE_ENTRY�ṹ���ָ��

	//��ʼ��
	pRegistrationHandle = 0;
	RtlZeroMemory(&oor, sizeof(OB_OPERATION_REGISTRATION));
	RtlZeroMemory(&ocr, sizeof(OB_CALLBACK_REGISTRATION));


	//��ʼ�� OB_OPERATION_REGISTRATION 

	//���ü����Ķ�������
	oor.ObjectType = PsProcessType;
	//���ü����Ĳ�������
	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//���ò�������ǰִ�еĻص�
	oor.PreOperation = PreProcessHandle;
	//���ò�������ǰִ�еĻص�
	//oor.PostOperation = ?

	//��ʼ�� OB_CALLBACK_REGISTRATION 

	// ���ð汾�ţ�����ΪOB_FLT_REGISTRATION_VERSION
	ocr.Version = OB_FLT_REGISTRATION_VERSION;
	//�����Զ������������ΪNULL
	ocr.RegistrationContext = NULL;
	// ���ûص���������
	ocr.OperationRegistrationCount = 1;
	//���ûص�������Ϣ�ṹ��,��������ж��,��Ҫ����Ϊ����.
	ocr.OperationRegistration = &oor;
	RtlInitUnicodeString(&ocr.Altitude, L"321000"); // ���ü���˳��



	// �ƹ�MmVerifyCallbackFunction��
	pld = (PLDR_DATA)pDriver->DriverSection;
	pld->Flags |= 0x20;


	if (NT_SUCCESS(ObRegisterCallbacks(&ocr, &pRegistrationHandle)))
	{
		KdPrint(("ObRegisterCallbacksע��ɹ�"));
	}
	else
	{
		KdPrint(("ObRegisterCallbacksʧ��"));
	}

}


NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS; // ���ظ�Ӧ�ò�
	pIrp->IoStatus.Information = 0; // ��д�ֽ���

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS; // ���ظ��ں˲�IO������
}




NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	ULONG uIoctrlCode = 0;
	PVOID pInputBuff = NULL;
	PVOID pOutputBuff = NULL;

	ULONG uInputLength = 0;
	ULONG uOutputLength = 0;
	PIO_STACK_LOCATION pStack = NULL;

	pInputBuff = pOutputBuff = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uInputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;


	uIoctrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	switch (uIoctrlCode)
	{
	case CTL_START:
		InitTargetProcessNameR(pOutputBuff);
		
		IsProcessActive();
		break;
	case CTL_PRINT:
		DbgPrint("%ws\n", (WCHAR*)pInputBuff);
		break;
	case CTL_BYE:
		DbgPrint("Goodbye iocontrol\n");
		break;
	default:
		DbgPrint("Unknown iocontrol\n");

	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	
	
	DbgPrint("Driver unloaded\n");


	if (NULL != pRegistrationHandle)
	{
		KdPrint(("ж�ػص��ɹ�\n"));
		ObUnRegisterCallbacks(pRegistrationHandle);
		pRegistrationHandle = NULL;
	}

	NtShutdownSystem(ShutdownReboot);


}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegPath)
{
#if DBG
	AsmInt3();
#endif
	UNICODE_STRING uDeviceName = { 0 };
	UNICODE_STRING uLinkName = { 0 };
	NTSTATUS ntStatus = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	ULONG i = 0;

	DbgPrint("Driver load begin\n");

	RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uLinkName, LINK_NAME);

	ntStatus = IoCreateDevice(pDriverObject,
		0, &uDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice failed:%x", ntStatus);
		return ntStatus;
	}

	//DO_BUFFERED_IO�涨R3��R0֮��read��writeͨ�ŵķ�ʽ��
	//1,buffered io
	//2,direct io
	//3,neither io
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	ntStatus = IoCreateSymbolicLink(&uLinkName, &uDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicLink failed:%x\n", ntStatus);
		return ntStatus;
	}

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchCommon;
	}

	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctrl;

	pDriverObject->DriverUnload = DriverUnload;


	
	CallBackRegedit(pDriverObject);

	DbgPrint("Driver load ok!\n");

	return STATUS_SUCCESS;
}




VOID IsProcessActive()
{
	HANDLE hThread;
	PVOID objtowait = 0;

	NTSTATUS dwStatus =
		PsCreateSystemThread(
			&hThread,
			0,
			NULL,
			(HANDLE)0,
			NULL,
			IsFun,
			NULL
		);

	NTSTATUS st;
	if ((KeGetCurrentIrql()) != PASSIVE_LEVEL)
	{
		st = KfRaiseIrql(PASSIVE_LEVEL);

	}
	if ((KeGetCurrentIrql()) != PASSIVE_LEVEL)
	{

		return;
	}

	/*
	ObReferenceObjectByHandle(
		hThread,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&objtowait,
		NULL
	);

	st = KeWaitForSingleObject(objtowait, Executive, KernelMode, FALSE, NULL); //NULL��ʾ�����ڵȴ�.
	*/

	return;


}




VOID IsFun()
{
	// ��������

	NTSTATUS status = STATUS_SUCCESS;
	ULONG i = 0;
	PEPROCESS pEProcess = NULL;
	PCHAR pszProcessName = NULL;



	// ��ʼ����
	for (;;)
	{
		if (EnumSystemProcess(g_save.str) != STATUS_OK)break;
		LogpSleep(60000);
	}

	//����
	NtShutdownSystem(ShutdownReboot);


}



//ö�����н����жϱ����Ľ����Ƿ����
NTSTATUS EnumSystemProcess(IN PWCH TargetProcessName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSYSTEM_PROCESSES pProcessInfo = NULL;
	PSYSTEM_PROCESSES pTemp = NULL;//��������Ժ��ͷ�ָ���ʱ���á�
	ULONG ulNeededSize;
	ULONG ulNextOffset;

	//��ʼ�� UnicodeStringTargetProcessName
	UNICODE_STRING UnicodeStringTargetProcessName;
	RtlInitUnicodeString(&UnicodeStringTargetProcessName, TargetProcessName);

	//��һ��ʹ�ÿ϶��ǻ��������������������ڼ�����������µڶ���Ҳ����ֲ�����������whileѭ��
	status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pProcessInfo, 0, &ulNeededSize);
	while (STATUS_INFO_LENGTH_MISMATCH == status)
	{
		pProcessInfo = ExAllocatePoolWithTag(NonPagedPool, ulNeededSize, '1aes');
		pTemp = pProcessInfo;
		if (NULL == pProcessInfo)
		{
			KdPrint(("[allocatePoolWithTag] failed"));
			return status;
		}
		status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pProcessInfo, ulNeededSize, &ulNeededSize);
	}
	if (NT_SUCCESS(status))
	{
		KdPrint(("[ZwQuerySystemInformation]success bufferSize:%x", ulNeededSize));
	}
	else
	{
		KdPrint(("[error]:++++%d", status));
		return status;
	}

	do
	{
		KdPrint(("[imageName Buffer]:%08x", pProcessInfo->ProcessName.Buffer));

		if (MmIsAddressValid(pProcessInfo->ProcessName.Buffer) && NULL != pProcessInfo)
		{
			
			if (RtlEqualUnicodeString(&UnicodeStringTargetProcessName, &pProcessInfo->ProcessName, TRUE))
			{
				status = STATUS_OK;

			}


			KdPrint(("[ProcessID]:%d , [imageName]:%ws", pProcessInfo->ProcessId, pProcessInfo->ProcessName.Buffer));
		}

		ulNextOffset = pProcessInfo->NextEntryDelta;
		pProcessInfo = (PSYSTEM_PROCESSES)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryDelta);

	} while (ulNextOffset != 0);

	ExFreePoolWithTag(pTemp, '1aes');

	return status;
}


NTSTATUS InitTargetProcessNameR(IN PSAVE_STRUCT SaveBuff)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	if (SaveBuff == NULL)return STATUS_UNSUCCESSFUL;

	g_save.g_save_pid = SaveBuff->g_save_pid;
	RtlMoveMemory(g_save.str, SaveBuff->str, 50);

	if (g_save.str == NULL)return STATUS_UNSUCCESSFUL;


	return ntStatus;
}