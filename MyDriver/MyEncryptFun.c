#include "MyEncryptFun.h"

/*************************************************************************
读取文件加密信息
*************************************************************************/
#pragma LOCKEDCODE
NTSTATUS GetFileEncryptInfoToCtx(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__inout PSTREAM_HANDLE_CONTEXT Ctx)
{
	NTSTATUS status;
	//初始化流加密信息
	Ctx->isEncrypted = IS_NOT_ENCRYPTED;
	Ctx->isEncryptFile = IS_NOT_ENCRYPT_FILE;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

	BOOLEAN isDir = FALSE;
	BOOLEAN is_encrypt_file = FALSE;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//判断是否是文件夹
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir);
//	DbgPrint("Dir status is : %ld", status);
	if (NT_SUCCESS(status))
	{
		if (isDir)
		{
			return status;
		}
		else
		{
			//获取文件名称
			status = FltGetFileNameInformation(
						Data,
						FLT_FILE_NAME_OPENED | 
						FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
						&nameInfo);
//			DbgPrint("Get file name information status is : %ld", status);
			if (NT_SUCCESS(status))
			{
				FltParseFileNameInformation(nameInfo);
				//判断是否是加密类型文件
				is_encrypt_file = IsInEncryptList(&(nameInfo->Extension));
				if (is_encrypt_file)
				{
//					DbgPrint("File name is %wZ,", &(nameInfo->Name));
//					DbgPrint("is a encrypt file.\n");
					Ctx->isEncryptFile = IS_ENCRYPT_FILE;

					//读取文件尾部，检查是否已经加密
					CHAR Mark[ENCRYPT_MARK_LEN];
					ULONG readlen = 0;

					//获取文件信息
					FILE_STANDARD_INFORMATION fileInfo;
					status = FltQueryInformationFile(
								FltObjects->Instance,
								Data->Iopb->TargetFileObject,
								&fileInfo,
								sizeof(FILE_STANDARD_INFORMATION),
								FileStandardInformation,
								NULL);
					//DbgPrint("Query information file status is : %ld",status);
					if (NT_SUCCESS(status))
					{
						//获取文件长度
						LONGLONG offset = fileInfo.EndOfFile.QuadPart - ENCRYPT_MARK_LEN;

//						DbgPrint("File offset is:%lld", offset);
						if (offset < 0)
						{
							Ctx->isEncrypted = IS_NOT_ENCRYPTED;
						}
						else
						{
							LARGE_INTEGER l_offset;
							l_offset.QuadPart = offset;
							//读取尾部
							status = FltReadFile(
										FltObjects->Instance,
										FltObjects->FileObject,
										&(l_offset),
										ENCRYPT_MARK_LEN,
										(PVOID)Mark,
										FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
										&readlen,
										NULL, NULL);
							//DbgPrint("Read information file status is : %ld", status);
							if (NT_SUCCESS(status))
							{
//								DbgPrint("Encrypt string  is %s",Mark);

								if (strncmp(Mark, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING)) == 0)
								{
									Ctx->isEncrypted = IS_ENCRYPTED;
								}
//								Ctx->isEncrypted = IS_ENCRYPTED;
//								DbgPrint("Encrypt status  is %x", Ctx->isEncrypted);
							}
							else
							{
								DbgPrint("Read file err when in get file info");
//								Ctx->isEncrypted = IS_NOT_ENCRYPTED;
							}
						}
					}
					else
					{
						DbgPrint("get file information failed!");
					}
				}
				else
				{
				//	DbgPrint("No a filt file");
				}
			}
			else
			{
			//	DbgPrint("Can not read filename");
			}
		}
	}
	else
	{
	//	DbgPrint("Test dir fail");
	}

	if (nameInfo != NULL)
	{
		FltReleaseFileNameInformation(nameInfo);
	}
	return status;
}

BOOLEAN IsInEncryptList(PUNICODE_STRING file_extention)
{
	//比较文件后缀名，判断是否是加密类型
	UNICODE_STRING extention;
	RtlInitUnicodeString(&extention, L"txt");
//	DbgPrint("file extention is %wZ", file_name);
//	DbgPrint("extention is %wZ",&extention);
	if (RtlCompareUnicodeString(file_extention,&extention,TRUE)==0)
		return TRUE;	
	return FALSE;
}


/*************************************************************************
清除文件缓冲
*************************************************************************/
void FileCacheClear(PFILE_OBJECT pFileObject)
{
	PFSRTL_COMMON_FCB_HEADER pFcb;
	LARGE_INTEGER liInterval;
	BOOLEAN bNeedReleaseResource = FALSE;
	BOOLEAN bNeedReleasePagingIoResource = FALSE;
	KIRQL irql;


	pFcb = (PFSRTL_COMMON_FCB_HEADER)pFileObject->FsContext;
	if (pFcb == NULL)
		return;

	irql = KeGetCurrentIrql();
	if (irql >= DISPATCH_LEVEL)
	{
		return;
	}

	liInterval.QuadPart = -1 * (LONGLONG)50;

	while (TRUE)
	{
		BOOLEAN bBreak = TRUE;
		BOOLEAN bLockedResource = FALSE;
		BOOLEAN bLockedPagingIoResource = FALSE;
		bNeedReleaseResource = FALSE;
		bNeedReleasePagingIoResource = FALSE;

		// 到fcb中去拿锁。
		if (pFcb->PagingIoResource)
			bLockedPagingIoResource = ExIsResourceAcquiredExclusiveLite(pFcb->PagingIoResource);

		// 总之一定要拿到这个锁。
		if (pFcb->Resource)
		{
			bLockedResource = TRUE;
			if (ExIsResourceAcquiredExclusiveLite(pFcb->Resource) == FALSE)
			{
				bNeedReleaseResource = TRUE;
				if (bLockedPagingIoResource)
				{
					if (ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE) == FALSE)
					{
						bBreak = FALSE;
						bNeedReleaseResource = FALSE;
						bLockedResource = FALSE;
					}
				}
				else
					ExAcquireResourceExclusiveLite(pFcb->Resource, TRUE);
			}
		}

		if (bLockedPagingIoResource == FALSE)
		{
			if (pFcb->PagingIoResource)
			{
				bLockedPagingIoResource = TRUE;
				bNeedReleasePagingIoResource = TRUE;
				if (bLockedResource)
				{
					if (ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE) == FALSE)
					{
						bBreak = FALSE;
						bLockedPagingIoResource = FALSE;
						bNeedReleasePagingIoResource = FALSE;
					}
				}
				else
				{
					ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, TRUE);
				}
			}
		}

		if (bBreak)
		{
			break;
		}

		if (bNeedReleasePagingIoResource)
		{
			ExReleaseResourceLite(pFcb->PagingIoResource);
		}
		if (bNeedReleaseResource)
		{
			ExReleaseResourceLite(pFcb->Resource);
		}

		if (irql == PASSIVE_LEVEL)
		{
			KeDelayExecutionThread(KernelMode, FALSE, &liInterval);
		}
		else
		{
			KEVENT waitEvent;
			KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
			KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, &liInterval);
		}
	}

	if (pFileObject->SectionObjectPointer)
	{
		IO_STATUS_BLOCK ioStatus;
		CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);

		if (NT_SUCCESS(ioStatus.Status))
		{
		//	KdPrint(("CcFlushCache OK\n"));
		}
		else
		{
			KdPrint(("CcFlushCache Failed\n"));
		}

		if (pFileObject->SectionObjectPointer->ImageSectionObject)
		{
			//MmFlushImageSection(pFileObject->SectionObjectPointer,MmFlushForWrite); // MmFlushForDelete


			if (MmFlushImageSection(pFileObject->SectionObjectPointer, MmFlushForWrite) == TRUE)
			{
				KdPrint(("MmFlushImageSection OK\n"));
			}
			else
			{
				KdPrint(("MmFlushImageSection Failed\n"));
			}
		}
		//CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, FALSE);

		if (CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, TRUE) == TRUE)
		{
		//	KdPrint(("CcPurgeCacheSection OK\n"));
		}
		else
		{
			KdPrint(("CcPurgeCacheSection Failed\n"));
		}

		/*
		{
			KEVENT waitEvent1;
			LARGE_INTEGER liInterval0;
			liInterval0.QuadPart = 0;
			KeInitializeEvent(&waitEvent1, NotificationEvent, FALSE);
			CcUninitializeCacheMap(pFileObject, &liInterval0, (PCACHE_UNINITIALIZE_EVENT)&waitEvent1);
			KeWaitForSingleObject(&waitEvent1, Executive, KernelMode, FALSE, &liInterval0);
		}*/

		//CcSetFileSizes(pFileObject,0);
	}

	if (bNeedReleasePagingIoResource)
	{
		ExReleaseResourceLite(pFcb->PagingIoResource);
	}
	if (bNeedReleaseResource)
	{
		ExReleaseResourceLite(pFcb->Resource);
	}
}


/*************************************************************************
获取进程名偏移
*************************************************************************/
ULONG GetProcessNameOffset(VOID)
{
	PEPROCESS	currentProc;
	int				i;

	currentProc = PsGetCurrentProcess();

	for (i = 0; i < 3 * PAGE_SIZE; i++)
	{
		if (!strncmp("System", (PCHAR)currentProc + i, strlen("System")))
		{
			return i;
		}
	}
	return 0;
}

/*************************************************************************
获取进程名称
*************************************************************************/
PCHAR GetCurrentProcessName(ULONG ProcessNameOffset)
{
	PEPROCESS		currentProc;
	char					*nameptr;

//	DbgPrint("in the GetCurrentProcessName function,process name offset is %ld",ProcessNameOffset);
	if (ProcessNameOffset)
	{
		currentProc = PsGetCurrentProcess();
		nameptr = (PCHAR)currentProc + ProcessNameOffset;
	}
	else
	{
		nameptr = "";
	}
//	DbgPrint("Current process name is %s", nameptr);
	return nameptr;
}

/*************************************************************************
加密文件
*************************************************************************/
NTSTATUS EncryptFile(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PCHAR key)
{
	NTSTATUS status;
	FILE_STANDARD_INFORMATION fileInfo;
	ULONG len = 0;

//	UNREFERENCED_PARAMETER(key);
//	UNREFERENCED_PARAMETER(Data);

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = FltQueryInformationFile(
				FltObjects->Instance,
				FltObjects->FileObject,
				&fileInfo,
				sizeof(FILE_STANDARD_INFORMATION),
				FileStandardInformation,
				&len);
	if (NT_SUCCESS(status))
	{
		LONGLONG fileLen = fileInfo.EndOfFile.QuadPart;
		ULONG bufferLen = 1024 * 1024;
		ULONG writeLen;
		ULONG readLen;
		LARGE_INTEGER offset;
		offset.QuadPart = 0;

		//申请缓冲区
		PVOID buff = ExAllocatePoolWithTag(
							NonPagedPool,
							bufferLen,
							BUFFER_SWAP_TAG);
		if (buff == NULL)
		{
			DbgPrint("No enough memoy.");
			return STATUS_UNSUCCESSFUL;
		}

		PMDL newMdl = IoAllocateMdl(
								buff,
								bufferLen,
								FALSE,
								FALSE,
								NULL);
		if (newMdl != NULL)
		{
			MmBuildMdlForNonPagedPool(newMdl);
		}
		//初始化内存
		RtlZeroMemory(buff, bufferLen);

		//加密文件
		LONGLONG hadWrite = 0;
		while (hadWrite < fileLen)
		{
			//读取文件
			status = FltReadFile(
						FltObjects->Instance,
						FltObjects->FileObject,
						&offset,
						bufferLen,
						buff,
						FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
						&readLen,
						NULL,NULL);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("read file error when move file content.");
				ExFreePool(buff);
				if (newMdl != NULL)
				{
					IoFreeMdl(newMdl);
				}
				return status;
			}
			//加密缓冲区
			//EncryptData(buff, buff, offset.QuadPart, readLen, key);

			char * indata = (char *)buff;

			DbgPrint("encrypt buff,encrypt buffer string is %s", buff);

			LONGLONG z = 0;
			while (z<readLen)
			{
				indata[z] = indata[z] ^ 0x01;
				z++;
			}

			DbgPrint("read buffer is %s",buff);

			status = FltWriteFile(
						FltObjects->Instance,
						FltObjects->FileObject,
						&offset,
						readLen,
						buff,
						0,
						&writeLen,
						NULL,NULL);
			if (readLen!=writeLen)
			{
				DbgPrint("wirte len not equal the read len.");
			}
			if (!NT_SUCCESS(status))
			{
				DbgPrint("write file error when move file content.");
				ExFreePool(buff);
				if (newMdl != NULL)
				{
					IoFreeMdl(newMdl);
				}
				return status;
			}
			offset.QuadPart += readLen;
			hadWrite += readLen;
		}

		//在尾部写入加密标识
		offset = fileInfo.EndOfFile;
		RtlZeroMemory(buff, bufferLen);
		RtlCopyMemory(buff, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING));

		DbgPrint("end of file buff is %s", buff);

		status = FltWriteFile(
					FltObjects->Instance,
					FltObjects->FileObject,
					&offset,
					ENCRYPT_MARK_LEN,
					buff,
					0,
					&writeLen,
					NULL,NULL);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("Encrypt file wrong when write.");
			ExFreePool(buff);
			if (newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}
			return status;
		}

		ExFreePool(buff);
		if (newMdl != NULL)
		{
			IoFreeMdl(newMdl);
		}
		return status;
	}

	return status;
}
/*************************************************************************
往缓冲区写入文件尾部
*************************************************************************/
void WriteEncryptTrail(PVOID buff, ULONG offset)
{
	CHAR mark[128];

	RtlZeroMemory(mark, ENCRYPT_MARK_LEN);

	RtlCopyMemory((PVOID)mark, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING));

	PCHAR c = (PCHAR)buff;

	RtlCopyMemory((PVOID)(&(c[offset])), (PVOID)mark, ENCRYPT_MARK_LEN);
}