#ifndef __MYENCRYPTFUN_H__
#define __MYENCRYPTFUN_H__

#include "MyDriver.h"

#define		ENCRYPT_MARK_LEN	128		//���ܱ�־����
#define		ENCRYPT_FILE_CONTENT_OFFSET		128	//�����ļ�����ƫ��

#define		ENCRYPT_MARK_STRING	"-------This file has been encrypted-------"	//���ܱ�ʶ��


//��ȡ�ļ�������Ϣ
NTSTATUS GetFileEncryptInfoToCtx(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__inout PSTREAM_HANDLE_CONTEXT Ctx
);
BOOLEAN IsInEncryptList(PUNICODE_STRING file_extention);

//��ȡ������ƫ�ơ���������
ULONG GetProcessNameOffset(VOID);
PCHAR GetCurrentProcessName(ULONG ProcessNameOffset);

//����ļ���������
void FileCacheClear(PFILE_OBJECT pFileObject);

//�����ļ�
NTSTATUS EncryptFile(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PCHAR key
);

//д���ļ�β��
void WriteEncryptTrail(PVOID buff, ULONG offset);
#endif
