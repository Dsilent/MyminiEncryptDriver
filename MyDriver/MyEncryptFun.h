#ifndef __MYENCRYPTFUN_H__
#define __MYENCRYPTFUN_H__

#include "MyDriver.h"

#define		ENCRYPT_MARK_LEN	128		//加密标志长度
#define		ENCRYPT_FILE_CONTENT_OFFSET		128	//加密文件内容偏移

#define		ENCRYPT_MARK_STRING	"-------This file has been encrypted-------"	//加密标识符


//获取文件加密信息
NTSTATUS GetFileEncryptInfoToCtx(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__inout PSTREAM_HANDLE_CONTEXT Ctx
);
BOOLEAN IsInEncryptList(PUNICODE_STRING file_extention);

//获取进程名偏移、进程名称
ULONG GetProcessNameOffset(VOID);
PCHAR GetCurrentProcessName(ULONG ProcessNameOffset);

//清除文件缓冲数据
void FileCacheClear(PFILE_OBJECT pFileObject);

//加密文件
NTSTATUS EncryptFile(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PCHAR key
);

//写入文件尾部
void WriteEncryptTrail(PVOID buff, ULONG offset);
#endif
