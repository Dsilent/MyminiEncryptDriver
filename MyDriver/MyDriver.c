/*++

Module Name:

    MyDriver.c

Abstract:

    This is the main module of the MyDriver miniFilter driver.

Environment:

    Kernel mode

--*/

#include "MyDriver.h"
#include "MyEncryptFun.h"
#include "ctx.h"


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
ULONG gTraceFlags = 0;

#define		KEY_MAX_LEN			32				//密钥最大长度
CHAR key[KEY_MAX_LEN] = { "nuaa" };		//加解密密钥
ULONG ProcessNameOffset = 0;				//进程名偏移

NPAGED_LOOKASIDE_LIST Pre2PostContextList; //传递上下文列表

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MyDriverUnload)
#pragma alloc_text(PAGE, MyDriverInstanceQueryTeardown)
#pragma alloc_text(PAGE, MyDriverInstanceSetup)
#pragma alloc_text(PAGE, MyDriverInstanceTeardownStart)
#pragma alloc_text(PAGE, MyDriverInstanceTeardownComplete)
#endif
//
//  context registration
//
//上下文注册结构体

CONST FLT_CONTEXT_REGISTRATION ContextNotifications[] = {
	{
		FLT_STREAMHANDLE_CONTEXT,
		0,
		NULL,

		sizeof(STREAM_HANDLE_CONTEXT),
		STREAMHANDLE_CONTEXT_TAG
	},
	{ FLT_CONTEXT_END }
};


//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      MyDriverPreCreate,
      MyDriverPostCreate},

	  { IRP_MJ_READ,
	  0,
	  MyDriverPreRead,
	  MyDriverPostRead},

	  { IRP_MJ_WRITE,
	  0,
	  MyDriverPreWrite,
	  MyDriverPostWrite },
	  
	  { IRP_MJ_CLEANUP,
	  0,
	  MyDriverPreClose,
	  MyDriverPostClose },

	  { IRP_MJ_QUERY_INFORMATION,
	  0,
	  MyDriverPreQueryInformation,
	  MyDriverPostQueryInformation },
	 
	  { IRP_MJ_SET_INFORMATION,
	  0,
	  MyDriverPreSetInformation,
	  MyDriverPostSetInformation },

#if 0
	{ IRP_MJ_CREATE_NAMED_PIPE,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_CLOSE,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_READ,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_WRITE,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_SET_EA,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      MyDriverPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_PNP,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      MyDriverPreOperation,
      MyDriverPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

	ContextNotifications,           //  Context
    Callbacks,                          //  Operation callbacks

    MyDriverUnload,                           //  MiniFilterUnload

    MyDriverInstanceSetup,                    //  InstanceSetup
    MyDriverInstanceQueryTeardown,            //  InstanceQueryTeardown
    MyDriverInstanceTeardownStart,            //  InstanceTeardownStart
    MyDriverInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
MyDriverInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!MyDriverInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
MyDriverInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!MyDriverInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
MyDriverInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!MyDriverInstanceTeardownStart: Entered\n") );
}


VOID
MyDriverInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!MyDriverInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!DriverEntry: Entered\n") );

	ProcessNameOffset = GetProcessNameOffset();

	DbgPrint("process name offset is %ld", ProcessNameOffset);

	//初始化NPAGED_LOOKASIDE_LIST
	ExInitializeNPagedLookasideList(&Pre2PostContextList,
		NULL,
		NULL,
		0,
		sizeof(PRE_2_POST_CONTEXT),
		PRE_TO_POST_TAG,
		0);

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
MyDriverUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!MyDriverUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );
	ExDeleteNPagedLookasideList(&Pre2PostContextList);
    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
MyDriverPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!MyDriverPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (MyDriverDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    MyDriverOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("MyDriver!MyDriverPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
MyDriverOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!MyDriverOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("MyDriver!MyDriverOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
MyDriverPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!MyDriverPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
MyDriverPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MyDriver!MyDriverPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
MyDriverDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

/*************************************************************************
自定义回调函数
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
MyDriverPreCreate(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	//创建文件请求完成前什么都不做
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
MyDriverPostCreate(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	NTSTATUS status;
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PSTREAM_HANDLE_CONTEXT	pCtx = NULL;
	STREAM_HANDLE_CONTEXT		tempCtx;

	//检查请求中断级，大于等于DISPATCH_LEVEL则直接结束返回
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	__try
	{
			//初始化临时流上下文
			tempCtx.isEncryptFile = IS_NOT_ENCRYPT_FILE;
			tempCtx.isEncrypted = IS_NOT_ENCRYPTED;

			//获取文件的加密信息
			status = GetFileEncryptInfoToCtx(Data, FltObjects, &tempCtx);
			if (!NT_SUCCESS(status))
			{
//				DbgPrint("get file encrypt information failed.\n");
				return FLT_POSTOP_FINISHED_PROCESSING;
			}
			
			//若不是加密类型文件，直接跳过
			if (tempCtx.isEncryptFile != IS_ENCRYPT_FILE)
			{
//				DbgPrint("File is not an encrypt file!");
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			FileCacheClear(FltObjects->FileObject);

			//获取流上下文，创建文件时没有流上下文需创建
			status = FltGetStreamHandleContext(FltObjects->Instance,FltObjects->FileObject,&pCtx);
//			DbgPrint("Get stream handle context status is :%ld",status);
			if (!NT_SUCCESS(status))
			{
				//创建流上下文
				status = FltAllocateContext(
							FltObjects->Filter,
							FLT_STREAMHANDLE_CONTEXT,
							sizeof(STREAM_HANDLE_CONTEXT),
							NonPagedPool,
							&pCtx);
				//创建流上下文失败
//				DbgPrint("Get Allocate context status is :%ld", status);
				if (!NT_SUCCESS(status))
				{
					return FLT_POSTOP_FINISHED_PROCESSING;
				}

				PFLT_CONTEXT oldCtx;
				//设置流句柄上下文
				status = FltSetStreamHandleContext(
							FltObjects->Instance,
							FltObjects->FileObject,
							FLT_SET_CONTEXT_KEEP_IF_EXISTS,
							pCtx,
							&oldCtx);
//				DbgPrint("Set stream handle context status is :%ld", status);
				if (oldCtx != NULL)
				{
					pCtx = (PSTREAM_HANDLE_CONTEXT)oldCtx;
					FltReleaseContext(oldCtx);
				}
				if (!NT_SUCCESS(status))
				{
					return FLT_POSTOP_FINISHED_PROCESSING;
				}
			}

			//流上下文信息赋值
			pCtx->isEncrypted = tempCtx.isEncrypted;
			pCtx->isEncryptFile = tempCtx.isEncryptFile;

//			DbgPrint("File encrypted status is :%d", pCtx->isEncrypted);
			
			//若文件未加密,加密文件
			if (pCtx->isEncrypted == IS_NOT_ENCRYPTED)
			{
				//获取当前进程名称
				PCHAR procName = GetCurrentProcessName(ProcessNameOffset);
//				DbgPrint("Current process name is：%s", procName);
				//当前进程为机密进程，加密文件
				if (strncmp(procName,"notepad.exe",strlen(procName))==0)
				{
					status = EncryptFile(Data, FltObjects, key);
//					DbgPrint("Encrypt a file");
					if (NT_SUCCESS(status))
					{
						pCtx->isEncrypted = IS_ENCRYPTED;
					}
					else
					{
						DbgPrint("Encrypt a file fail");
					}
				}
			}

			//获取文件信息，传递给后续例程
			status = FltQueryInformationFile(
						FltObjects->Instance,
						Data->Iopb->TargetFileObject,
						&(pCtx->fileInfo),
						sizeof(FILE_STANDARD_INFORMATION),
						FileStandardInformation,
						NULL);
			//清除缓冲
			FileCacheClear(FltObjects->FileObject);
			if (pCtx != NULL)
			{
				FltReleaseContext(pCtx);
			}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("a exception happened in postCreate"));

		//释放流上下文
		if (pCtx != NULL)
		{
			FltReleaseContext(pCtx);
		}
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
MyDriverPreRead(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	NTSTATUS status;
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;

	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	ULONG readlen = iopb->Parameters.Read.Length;

	PVOID newBuf = NULL;
	PMDL newMdl = NULL;

	PPRE_2_POST_CONTEXT p2pCtx;
	PSTREAM_HANDLE_CONTEXT pCtx = NULL;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	__try
	{
		//获取流上下文
		status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&pCtx);

		if (!NT_SUCCESS(status))
		{
			return retValue;
		}
		DbgPrint("get stream handle context in preRead successfully.");

		if (pCtx->isEncrypted == IS_NOT_ENCRYPTED)
		{
			__leave;
		}

		//是否机密进程
		PCHAR procName = GetCurrentProcessName(ProcessNameOffset);
		DbgPrint("Current process name is：%s", procName);
		if (strncmp(procName, "notepad.exe", strlen(procName)) != 0)
		{
			__leave;
		}

		//拒绝FAST I\O请求
		if (FLT_IS_FASTIO_OPERATION(Data))
		{
			retValue = FLT_PREOP_DISALLOW_FASTIO;
			__leave;
		}

		//缓冲读写跳过
		if (!(Data->Iopb->IrpFlags & (IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)))
		{
			__leave;
		}

		//读偏移大于等于文件真正长度时，结束请求
		if (iopb->Parameters.Read.ByteOffset.QuadPart >= pCtx->fileInfo.EndOfFile.QuadPart)
		{
			Data->IoStatus.Status = STATUS_END_OF_FILE;
			Data->IoStatus.Information = 0;
			retValue = FLT_PREOP_COMPLETE;
			__leave;
		}

		// 读长度为0，跳过
		if (readlen == 0)
		{
			__leave;
		}

		//申请分配非分页缓冲池
		newBuf = ExAllocatePoolWithTag(NonPagedPool, readlen, BUFFER_SWAP_TAG);
		if (newBuf == NULL)
		{
			__leave;
		}

		//简历MDL
		if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
		{
			newMdl = IoAllocateMdl(newBuf, readlen, FALSE, FALSE, NULL);
			if (newMdl == NULL)
			{
				__leave;
			}
			MmBuildMdlForNonPagedPool(newMdl);
		}

		p2pCtx = ExAllocateFromNPagedLookasideList(&Pre2PostContextList);
		if (p2pCtx == NULL)
		{
			__leave;
		}

		//交换缓冲区
		iopb->Parameters.Read.ReadBuffer = newBuf;
		iopb->Parameters.Read.MdlAddress = newMdl;
		FltSetCallbackDataDirty(Data);//通知filter管理器buffer地址和MDL地址已改变

		//保存新缓冲区到上下文
		p2pCtx->SwappedBuffer = newBuf;
		p2pCtx->IS_ENCODE = TRUE;
		*CompletionContext = p2pCtx;

		retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	finally{
		if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
		{
			if (newBuf != NULL)
			{
				ExFreePool(newBuf);
			}
			if (newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}
		}
	}
	if (pCtx != NULL)
	{
		FltReleaseContext(pCtx);
	}
	return retValue;
}

FLT_POSTOP_CALLBACK_STATUS
MyDriverPostRead(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	/*
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);*/

	NTSTATUS status = STATUS_SUCCESS;
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	PVOID origBuf;
	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
	BOOLEAN cleanupAllocatedBuffer = TRUE;

	ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));

	try{
		if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Information == 0))
		{
			leave;
		}
		if (iopb->Parameters.Read.MdlAddress != NULL)
		{
			origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority);
			if (origBuf == NULL)
			{
				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				leave;
			}
		}
		else if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) || FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
		{
			origBuf = iopb->Parameters.Read.ReadBuffer;
		}
		else
		{
			if (FltDoCompletionProcessingWhenSafe(Data,
																			FltObjects,
																			CompletionContext,
																			Flags,
																			SwapPostReadBuffersWhenSafe,
																			&retValue))
			{
				cleanupAllocatedBuffer = FALSE;
			}
			else
			{
				Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
				Data->IoStatus.Information = 0;
			}
			leave;
		}
		try{
			do
			{
				//解密
				if (p2pCtx->IS_ENCODE)
				{
					DbgPrint("decode in post read.");
					DbgPrint("decode in post read,decode buffer string is %s", p2pCtx->SwappedBuffer);

					LONGLONG buffLen  = Data->IoStatus.Information;
					char * indata = (char *)p2pCtx->SwappedBuffer;
//					char * outdata = (char *)p2pCtx->SwappedBuffer;

					LONGLONG z = 0;
					while (z<buffLen)
					{
						indata[z] = indata[z] ^ 0x01;
						z++;
					}	
					DbgPrint("decode in post read,after decode buffer string is %s", p2pCtx->SwappedBuffer);
				}
			} while (FALSE);
			//把置换缓冲区数据拷贝到原缓冲
			RtlCopyMemory(origBuf, p2pCtx->SwappedBuffer, Data->IoStatus.Information);

	}except(EXCEPTION_EXECUTE_HANDLER) {
		Data->IoStatus.Status = GetExceptionCode();
		Data->IoStatus.Information = 0;
		}
	}finally{
				if (cleanupAllocatedBuffer)
				{
				ExFreePool(p2pCtx->SwappedBuffer);
				ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
				}
			}
	return retValue;
}


FLT_POSTOP_CALLBACK_STATUS
SwapPostReadBuffersWhenSafe(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__in PVOID CompletionContext,
__in FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

We had an arbitrary users buffer without a MDL so we needed to get
to a safe IRQL so we could lock it and then copy the data.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - Contains state from our PreOperation callback

Flags - Denotes whether the completion is successful or is being drained.

Return Value:

FLT_POSTOP_FINISHED_PROCESSING - This is always returned.

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
	PVOID origBuf;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	ASSERT(Data->IoStatus.Information != 0);

	//
	//  This is some sort of user buffer without a MDL, lock the user buffer
	//  so we can access it.  This will create a MDL for it.
	//

	status = FltLockUserBuffer(Data);

	if (!NT_SUCCESS(status)) {

		DbgPrint("lock the buffer fail.");

		//
		//  If we can't lock the buffer, fail the operation
		//

		Data->IoStatus.Status = status;
		Data->IoStatus.Information = 0;

	}
	else {

		//
		//  Get a system address for this buffer.
		//

		origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress,
			NormalPagePriority);

		if (origBuf == NULL) {

			DbgPrint("can't get a system buffer address,fail the operation.");

			//
			//  If we couldn't get a SYSTEM buffer address, fail the operation
			//

			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			Data->IoStatus.Information = 0;

		}
		else {

			//
			//  Copy the data back to the original buffer.  Note that we
			//  don't need a try/except because we will always have a system
			//  buffer address.
			//

			RtlCopyMemory(origBuf,
				p2pCtx->SwappedBuffer,
				Data->IoStatus.Information);
		}
	}

	//
	//  Free allocated memory and release the volume context
	//

	DbgPrint(" Free allocated memory and release the volume context.");

	ExFreePool(p2pCtx->SwappedBuffer);
	p2pCtx->SwappedBuffer = NULL;
	ExFreeToNPagedLookasideList(&Pre2PostContextList,
		p2pCtx);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
MyDriverPreWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	NTSTATUS status;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;

	PVOID newBuf = NULL;
	PMDL newMdl = NULL;
	PPRE_2_POST_CONTEXT p2pCtx;
	PSTREAM_HANDLE_CONTEXT pCtx = NULL;

	PVOID origBuf;
	ULONG writeLen = iopb->Parameters.Write.Length;
	LARGE_INTEGER writeOffset = iopb->Parameters.Write.ByteOffset;

	KIRQL OldIrql;

	try{
		status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&pCtx);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}
		DbgPrint("get stream handle context in preWrite successfully.");

		//是否加密文件类型
		if (pCtx->isEncrypted == IS_NOT_ENCRYPTED)
		{
			__leave;
		}

		//是否机密进程
		PCHAR procName = GetCurrentProcessName(ProcessNameOffset);
		DbgPrint("Current process name is：%s", procName);
		if (strncmp(procName, "notepad.exe", strlen(procName)) != 0)
		{
			__leave;
		}

		//拒绝缓冲写请求
		if (FLT_IS_FASTIO_OPERATION(Data))
		{
			retValue = FLT_PREOP_DISALLOW_FASTIO;
			__leave;
		}

		//文件不可写
		if ( ! FltObjects->FileObject->WriteAccess)
		{
			__leave;
		}

		/*
		//如果不是缓冲读写请求,及时更新文件大小,防止缓冲写请求改变了文件大小
		if (!(Data->Iopb->IrpFlags & (IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)))
		{
			SC_LOCK(pCtx,&OldIrql);
			//写长度加写偏移比文件实际长度大，则需调整
			if ((writeLen + writeOffset.QuadPart) > pCtx->fileInfo.EndOfFile.QuadPart)
			{
				pCtx->fileInfo.EndOfFile.QuadPart = writeLen + writeOffset.QuadPart;
			}
			SC_UNLOCK(pCtx, OldIrql);
			__leave;
		}*/

		if (writeLen == 0)
		{
			leave;
		}

		newBuf = ExAllocatePoolWithTag(NonPagedPool, writeLen, BUFFER_SWAP_TAG);
		if (newBuf == NULL)
		{
			leave;
		}

		if (FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_IRP_OPERATION))
		{
			newMdl = IoAllocateMdl(newBuf, writeLen, FALSE, FALSE, NULL);
			if (newMdl == NULL)
			{
				leave;
			}
			MmBuildMdlForNonPagedPool(newMdl);
		}

		if (iopb->Parameters.Write.MdlAddress != NULL)
		{
			origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Write.MdlAddress, NormalPagePriority);
			if (origBuf ==NULL)
			{
				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				retValue = FLT_PREOP_COMPLETE;
				leave;
			}
		}
		else
		{
			origBuf = iopb->Parameters.Write.WriteBuffer;
		}
		try{
			//复制原缓冲区内容到新缓冲
			RtlCopyMemory(newBuf,origBuf,writeLen);
			do
			{
				DbgPrint("encrypt file buffer in preWrite");
				//加密新缓冲
//				LONGLONG buffLen = Data->IoStatus.Information;
				char * indata = (char *)newBuf;

				DbgPrint("encrypt in preWrite,decode buffer string is %s", newBuf);

				LONGLONG z = 0;
				while (z<writeLen)
				{
					indata[z] = indata[z] ^ 0x01;
//					newBuf[z] = indata[z];
					z++;
				}
				DbgPrint("encrypt in preWrite,after decode buffer string is %s", newBuf);

				//往新缓冲写入文件尾
//				WriteEncryptTrail(newBuf, iopb->Parameters.Write.Length);
				
				break;
			} while (FALSE);

		}except(EXCEPTION_EXECUTE_HANDLER){
			Data->IoStatus.Status = GetExceptionCode();
			Data->IoStatus.Information = 0;
			retValue = FLT_PREOP_COMPLETE;
			leave;
		}

		p2pCtx = ExAllocateFromNPagedLookasideList(&Pre2PostContextList);
		if (p2pCtx ==NULL)
		{
			leave;
		}

		iopb->Parameters.Write.WriteBuffer = newBuf;
		iopb->Parameters.Write.MdlAddress = newMdl;
		FltSetCallbackDataDirty(Data);

		p2pCtx->SwappedBuffer = newBuf;
		p2pCtx->IS_ENCODE = IS_ENCRYPTED;
		*CompletionContext = p2pCtx;

		retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	finally{
		if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
		{
			if (newBuf != NULL)
			{
				ExFreePool(newBuf);
			}
			if (newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}
		}	
	}

	if (pCtx != NULL)
	{
		FltReleaseContext(pCtx);
	}
	return retValue;
}

FLT_POSTOP_CALLBACK_STATUS
MyDriverPostWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
//	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;

	ExFreePool(p2pCtx->SwappedBuffer);
	ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
MyDriverPreClose(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	PSTREAM_HANDLE_CONTEXT ctx;

	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	NTSTATUS status = FltGetStreamHandleContext(FltObjects->Instance,FltObjects->FileObject,(PFLT_CONTEXT *)&ctx);
	if (NT_SUCCESS(status))
	{
		STREAM_HANDLE_CONTEXT tempCtx;
		tempCtx.isEncryptFile = IS_NOT_ENCRYPT_FILE;
		tempCtx.isEncrypted = IS_NOT_ENCRYPTED;

		status = GetFileEncryptInfoToCtx(Data, FltObjects, &tempCtx);
		if (!NT_SUCCESS(status))
		{
			return retValue;
		}

		//不是加密类型文件
		if (tempCtx.isEncryptFile == IS_NOT_ENCRYPT_FILE)
		{
			return retValue;
		}
		ctx->isEncryptFile = tempCtx.isEncryptFile;

		if (tempCtx.isEncrypted == IS_NOT_ENCRYPTED)
		{
			PCHAR proName = GetCurrentProcessName(ProcessNameOffset);
			if (strncmp(proName,"notepad.exe",strlen(proName)) == 0)
			{
				status = EncryptFile(Data, FltObjects, key);
				if (NT_SUCCESS(status))
				{
					ctx->isEncrypted = IS_ENCRYPTED;
				}
				else
				{
					DbgPrint("encrypt file fail.");
				}
			}
		}
	}

	if (ctx != NULL)
	{
		FltReleaseContext(ctx);
	}

	return retValue;
}

FLT_POSTOP_CALLBACK_STATUS
MyDriverPostClose(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;

	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	return retValue;
}

FLT_PREOP_CALLBACK_STATUS
MyDriverPreQueryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
MyDriverPostQueryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	STREAM_HANDLE_CONTEXT ctx;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	__try
	{
		//获取加密信息
		NTSTATUS status = GetFileEncryptInfoToCtx(Data, FltObjects, &ctx);

//		DbgPrint("Get file encrypt information to context status is %ld",status);
//		DbgPrint("Query file encrypt information,the isEncrypted flag is %d",ctx.isEncrypted);

		if (NT_SUCCESS(status))
		{
			//是加密类型且已加密
			if (ctx.isEncrypted == IS_ENCRYPTED)
			{
				PCHAR procName = GetCurrentProcessName(ProcessNameOffset);

				if (!strncmp(procName, "notepad.exe", strlen(procName)) == 0)
				{
					return FLT_POSTOP_FINISHED_PROCESSING;
				}

				//修改信息的文件长度
				PVOID buff = iopb->Parameters.QueryFileInformation.InfoBuffer;
				//请求类型
				switch (iopb->Parameters.QueryFileInformation.FileInformationClass)
				{
				case FileStandardInformation:
				{
					DbgPrint("FileStandarInformation");
					PFILE_STANDARD_INFORMATION stand_info = (PFILE_STANDARD_INFORMATION)buff;
					stand_info->AllocationSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					stand_info->EndOfFile.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FileAllInformation:
				{
					DbgPrint("QueryFileAllInformation");
					PFILE_ALL_INFORMATION all_info = (PFILE_ALL_INFORMATION)buff;
					if (Data->IoStatus.Information >= sizeof(FILE_BASIC_INFORMATION) + sizeof(FILE_STANDARD_INFORMATION))
					{
						all_info->StandardInformation.AllocationSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
						all_info->StandardInformation.EndOfFile.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;

						if (Data->IoStatus.Information >=
							sizeof(FILE_BASIC_INFORMATION) +
							sizeof(FILE_STANDARD_INFORMATION) +
							sizeof(FILE_EA_INFORMATION) +
							sizeof(FILE_ACCESS_INFORMATION) +
							sizeof(FILE_POSITION_INFORMATION))
						{
							all_info->PositionInformation.CurrentByteOffset.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
						}
					}
					break;
				}
				case FileAllocationInformation:
				{
					DbgPrint("QueryFileAllocationInformation");
					PFILE_ALLOCATION_INFORMATION alloc_info = (PFILE_ALLOCATION_INFORMATION)buff;
					alloc_info->AllocationSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FileValidDataLengthInformation:
				{
					DbgPrint("QueryFileValidDataLengthInformation");
					PFILE_VALID_DATA_LENGTH_INFORMATION valid_info = (PFILE_VALID_DATA_LENGTH_INFORMATION)buff;
					valid_info->ValidDataLength.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FileEndOfFileInformation:
				{
					DbgPrint("QueryFileEndOfFileInformation");
					PFILE_END_OF_FILE_INFORMATION end_info = (PFILE_END_OF_FILE_INFORMATION)buff;
					end_info->EndOfFile.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FilePositionInformation:
				{
					DbgPrint("QueryFilePositionInformation");
					PFILE_POSITION_INFORMATION pos_info = (PFILE_POSITION_INFORMATION)buff;
					pos_info->CurrentByteOffset.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FileStreamInformation:
				{
					DbgPrint("QueryFileStreamInformation");
					PFILE_STREAM_INFORMATION stream_info = (PFILE_STREAM_INFORMATION)buff;
					stream_info->StreamAllocationSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					stream_info->StreamSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				default:
				{
					DbgPrint("DEFAULT");
					DbgPrint("Query FileInformationClass is %d",iopb->Parameters.QueryFileInformation.FileInformationClass);
					break;
				}
				}
				FltSetCallbackDataDirty(Data);
			}
		}
		else
		{
//			DbgPrint("Get file encrypt info failed.");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Error happen in post info.");
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
MyDriverPreSetInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	STREAM_HANDLE_CONTEXT ctx;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	
	__try
	{
		NTSTATUS status = GetFileEncryptInfoToCtx(Data, FltObjects, &ctx);

		if (NT_SUCCESS(status))
		{
			//是加密类型并且已加密
			if (ctx.isEncrypted == IS_ENCRYPTED)
			{
				PCHAR procName = GetCurrentProcessName(ProcessNameOffset);
				DbgPrint("Current process name is：%s", procName);
				if (!strncmp(procName, "notepad.exe", strlen(procName)));
				{
					return FLT_PREOP_SUCCESS_WITH_CALLBACK;
				}

				//修改文件长度
				PVOID buffer = iopb->Parameters.SetFileInformation.InfoBuffer;
				//修改设置偏移
				switch (iopb->Parameters.SetFileInformation.FileInformationClass)
				{

				case FileStandardInformation:
				{
					DbgPrint("SetFileStandardInformation");
					PFILE_STANDARD_INFORMATION stand_info = (PFILE_STANDARD_INFORMATION)buffer;
					stand_info->AllocationSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					stand_info->EndOfFile.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FileAllInformation:
				{
					DbgPrint("SetFileAllInformation");
					PFILE_ALL_INFORMATION all_info = (PFILE_ALL_INFORMATION)buffer;
					if (Data->IoStatus.Information >=
						sizeof(FILE_BASIC_INFORMATION) +
						sizeof(FILE_STANDARD_INFORMATION))
					{
						all_info->StandardInformation.AllocationSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
						all_info->StandardInformation.EndOfFile.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;

						if (Data->IoStatus.Information >=
							sizeof(FILE_BASIC_INFORMATION) +
							sizeof(FILE_STANDARD_INFORMATION) +
							sizeof(FILE_EA_INFORMATION) +
							sizeof(FILE_ACCESS_INFORMATION) +
							sizeof(FILE_POSITION_INFORMATION))
						{
							all_info->PositionInformation.CurrentByteOffset.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
						}
					}
					break;
				}
				case FileAllocationInformation:
				{
					DbgPrint("SetFileAllocationInformation");
					PFILE_ALLOCATION_INFORMATION alloc_info = (PFILE_ALLOCATION_INFORMATION)buffer;
					alloc_info->AllocationSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FileValidDataLengthInformation:
				{
					DbgPrint("FileValidDataLengthInformation");
					PFILE_VALID_DATA_LENGTH_INFORMATION valid_info = (PFILE_VALID_DATA_LENGTH_INFORMATION)buffer;
					valid_info->ValidDataLength.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FileEndOfFileInformation:
				{
					DbgPrint("SetFileEndOfFileInformation");
					PFILE_END_OF_FILE_INFORMATION end_info = (PFILE_END_OF_FILE_INFORMATION)buffer;
					end_info->EndOfFile.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FilePositionInformation:
				{
					DbgPrint("SetFilePositionInformation");
					PFILE_POSITION_INFORMATION pos_info = (PFILE_POSITION_INFORMATION)buffer;
					pos_info->CurrentByteOffset.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				case FileStreamInformation:
				{
					DbgPrint("SetFileStreamInformation");
					PFILE_STREAM_INFORMATION stream_info = (PFILE_STREAM_INFORMATION)buffer;
					stream_info->StreamAllocationSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					stream_info->StreamSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}
				default:
				{
					DbgPrint("DEFAULT");
					DbgPrint("SetFileInformationClass is %d", iopb->Parameters.QueryFileInformation.FileInformationClass);
					break;
				}
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
MyDriverPostSetInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
		return FLT_POSTOP_FINISHED_PROCESSING;
	return FLT_POSTOP_FINISHED_PROCESSING;
}


/*
VOID 
CtxContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
	)
{
	STREAM_HANDLE_CONTEXT ctx = Context;
	
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ContextType);
	ASSERT(ContextType == FLT_STREAMHANDLE_CONTEXT);

	if (ctx->)
}*/