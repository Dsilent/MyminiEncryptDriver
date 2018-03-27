#ifndef  __CTX_H__
#define __CTX_H__

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#define IS_ENCRYPT_FILE 0x01
#define IS_NOT_ENCRYPT_FILE 0x00

#define IS_ENCRYPTED 0x01
#define IS_NOT_ENCRYPTED 0x00

#define BUFFER_SWAP_TAG     'swTg'
#define PRE_TO_POST_TAG      'pptg'
#define STREAMHANDLE_CONTEXT_TAG		'sctg'

#define SC_iLOCK(SC)\
	(ASSERT(KeGetCurrentIrql() <= APC_LEVEL), \
	ASSERT(ExIsResourceAcquiredExclusiveLite(SC) || \
	       !ExIsResourceAcquiredSharedLite(SC)),\
	 KeEnterCriticalRegion(),\
	 ExAcquireResourceExclusiveLite(SC, TRUE))

#define SC_iUNLOCK(SC) \
	(ASSERT(KeGetCurrentIrql() <= APC_LEVEL), \
	 ASSERT(ExIsResourceAcquiredSharedLite(SC) ||\
	         ExIsResourceAcquiredExclusiveLite(SC)),\
	 ExReleaseResourceLite(SC),\
	 KeLeaveCriticalRegion())

//流上下文信息
typedef struct _STREAM_HANDLE_CONTEXT{
	FILE_STANDARD_INFORMATION fileInfo;//文件信息
	INT isEncryptFile;//是否加密文件
	INT isEncrypted;//是否已经加密

	//Lock used to protect this context.
	PERESOURCE Resource;

	//Spin lock used to protect this context when irql is too high
	KSPIN_LOCK Resource1;
} STREAM_HANDLE_CONTEXT, *PSTREAM_HANDLE_CONTEXT;

typedef struct _PRE_2_POST_CONTEXT
{
	BOOLEAN IS_ENCODE;
	PVOID SwappedBuffer;
}PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;

VOID
SC_LOCK(PSTREAM_HANDLE_CONTEXT SC, PKIRQL OldIrql);

VOID
SC_UNLOCK(PSTREAM_HANDLE_CONTEXT SC, KIRQL OldIrql);

#endif