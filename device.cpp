/**************************************************************************

   Foresight Imaging WDM AVStream Driver

    Copyright (c) 2009-2010, Foresight Imaging, LLC

    File:

        device.cpp

    Abstract:

        This file contains the device level implementation of the AVStream
        driver.

    History:

        created 12/09/2008 - from Microsoft AVSHWS sample

**************************************************************************/
#include "ideadrv.h"
#include "formats.h"
#include "fsiprop.h"
#include <initguid.h>
#include <wdmguid.h>
#include <stdarg.h>
#include <string.h>

/**************************************************************************

    PAGEABLE CODE

**************************************************************************/

#ifdef ALLOC_PRAGMA
#pragma code_seg("PAGE")
#endif // ALLOC_PRAGMA

// log file when spilling debug information.  Mostly used for situations
// that occur during boot time when the debug viewer is not active.
#define DEFAULT_LOG_FILE_NAME	L"\\??\\C:\\ideadrv.log"

// Global for the Registry Path - have to store it this way because the only
// time it's available is during DriverEnty()
UNICODE_STRING gRegistryPath;

PDRIVER_DISPATCH   m_OrigDispatchControl;   // old dispatch for IRP_MJ_DEVICE_CONTROL
PDRIVER_DISPATCH   m_OrigDispatchCreate;    // old dispatch for IRP_MJ_CREATE
PDRIVER_DISPATCH   m_OrigDispatchClose;     // old dispatch for IRP_MJ_CLOSE
PDRIVER_DISPATCH   m_OrigDispatchCleanup;   // old dispatch for IRP_MJ_CLEANUP

DWORD     m_DeviceNum;

#define INITIALIZE_ALTERA_LOADING   0x00000001
#define INITIALIZE_ALTERA_LOADED    0x00000002

typedef struct {
  BoardHandle    bh;
  ULONG          dwReason;
} INITIALIZE_INFO;

typedef struct {
  I_SCATTER_LIST *pIScatterList;   // input Internal S/G list
  PSCATTER_GATHER_LIST pSysScatterGatherList; // output system list
} EXECUTION_CONTEXT;

void FillScatterGatherList(
    IN struct _DEVICE_OBJECT  *DeviceObject,
    IN struct _IRP  *Irp,
    IN PSCATTER_GATHER_LIST  ScatterGather,
    IN PVOID  Context
    );

PVOID __cdecl operator new
(
	size_t          iSize,
	_When_((poolType & NonPagedPoolMustSucceed) != 0,
		__drv_reportError("Must succeed pool allocations are forbidden. "
			"Allocation failures cause a system crash"))
	POOL_TYPE       poolType
	)
{
	PAGED_CODE();

	PVOID result = ExAllocatePoolWithTag(poolType, iSize, 'wNCK');

	if (result) {
		RtlZeroMemory(result, iSize);
	}

	return result;
}

PVOID __cdecl operator new
(
	size_t          iSize,
	_When_((poolType & NonPagedPoolMustSucceed) != 0,
		__drv_reportError("Must succeed pool allocations are forbidden. "
			"Allocation failures cause a system crash"))
	POOL_TYPE       poolType,
	ULONG           tag
	)
{
	PAGED_CODE();

	PVOID result = ExAllocatePoolWithTag(poolType, iSize, tag);

	if (result) {
		RtlZeroMemory(result, iSize);
	}

	return result;
}

void __cdecl operator delete(PVOID pVoid)
{
	PAGED_CODE();

	if (pVoid) {
		ExFreePool(pVoid);
	}
}

void __cdecl operator delete[](PVOID pVoid)
{
	PAGED_CODE();

}

void __cdecl operator delete(void *pVoid, size_t size)
{
	PAGED_CODE();

	if (pVoid) {
		ExFreePool(pVoid);
	}
}

void __cdecl operator delete[](void *pVoid, size_t size)
{
	PAGED_CODE();

}


/*************************************************************/

int strpos(char* pszString, char* pszSearchString, int nth)
{
	char* pszSearch = pszString;
	for (int i = 1; i <= nth; i++)
	{
		pszSearch = strstr(pszSearch, pszSearchString);
		
		if (!pszSearch)
			return -1;
		else if (i != nth)
			pszSearch++;
	}
	return (int)(pszSearch - pszString);
}

static LARGE_INTEGER PCStartingTime = { 0 };
static LARGE_INTEGER PCFrequency = { 1000000 };  // Prevent div by 0
static LARGE_INTEGER PreviousMicroseconds = { 0 };

void DecoratedDebug(char* pszFunction, char* pszSerial, char* pszFormat, ...)
{
	char __szDebugString[2048];
	char __szOutputString[2048];
	char __szFuncName[256];

	if(PCStartingTime.QuadPart == 0)
		PCStartingTime = KeQueryPerformanceCounter(&PCFrequency);

	LARGE_INTEGER Now;
	LARGE_INTEGER ElapsedMicroseconds;
	DWORD dwms;
	DWORD dwus;
	DWORD dwmsDiff;
	DWORD dwusDiff;

	Now = KeQueryPerformanceCounter(NULL);
	ElapsedMicroseconds.QuadPart = Now.QuadPart - PCStartingTime.QuadPart;
	ElapsedMicroseconds.QuadPart *= 1000000;
	ElapsedMicroseconds.QuadPart /= PCFrequency.QuadPart;
	dwms = (DWORD)(ElapsedMicroseconds.QuadPart / 1000);
	dwus = (DWORD)(ElapsedMicroseconds.QuadPart - (dwms * 1000));
	dwmsDiff = (DWORD)((ElapsedMicroseconds.QuadPart - PreviousMicroseconds.QuadPart)/ 1000);
	dwusDiff = (DWORD)((ElapsedMicroseconds.QuadPart - PreviousMicroseconds.QuadPart) - (dwmsDiff * 1000));
	PreviousMicroseconds = ElapsedMicroseconds;

	va_list arguments;
	va_start(arguments, pszFormat);
	vsprintf_s(__szDebugString, pszFormat, arguments);
	va_end(arguments);
	int FunctionNamePosition = strpos(pszFunction, " ", 2);
	int ParenthesiPosition = strpos(pszFunction, "(", 1);

	// If 2 spaces not found function signature has no return type, look for first space
	if(FunctionNamePosition == -1 || FunctionNamePosition > ParenthesiPosition)
		FunctionNamePosition = strpos(pszFunction, " ", 1);

	if (FunctionNamePosition != -1)
	{
		FunctionNamePosition++;
		int ParenthesisOffset = ParenthesiPosition - FunctionNamePosition;
		strncpy_s(__szFuncName, &pszFunction[FunctionNamePosition], ParenthesisOffset + 1);
		__szFuncName[ParenthesisOffset + 1] = ')';
		__szFuncName[ParenthesisOffset + 2] = '\0';
	}
	else
	{
		strcpy_s(__szFuncName, "FunctionNameUndefined");
	}

	sprintf_s(__szOutputString, "[%08d.%03dms] [%03d.%03dms] %s - %s\r\n", dwms, dwus , dwmsDiff, dwusDiff, __szFuncName, __szDebugString);

	FSI_LogMessage( __szOutputString );
	DbgPrint((__szOutputString));
}

static char FileNameBuffer[1024];

BOOLEAN FSI_LogMessage(PCHAR pBuffer)
/*++

Routine Description:
Print a message to the debug log file.  This should only
be used for messages generated during boot time that can't
be captured by a user-level debug message viewer.

Arguments:
The message string

Return Value:

--*/
{
	// kjm - don't write to a file if the IRQL is too high, not permitted
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return FALSE;
	}

//#if defined (DBG)
	ULONG Length;
	IO_STATUS_BLOCK  IoStatus;
	OBJECT_ATTRIBUTES objectAttributes;
	NTSTATUS status;
	HANDLE FileHandle;
	UNICODE_STRING fileName;
	static BOOL isLogging = FALSE;

	if (isLogging)
	{
		LARGE_INTEGER liDelay;
		liDelay.QuadPart = 1 * KE_TIME_1MS_RELATIVE;

		for (int n = 0; n < 100; n++)
		{
			KeDelayExecutionThread(KernelMode, FALSE, &liDelay);

			if (!isLogging)
				break;
		}
	}

	isLogging = TRUE;

	//get a handle to the log file object
	fileName.Buffer = NULL;
	fileName.Length = 0;
//	fileName.MaximumLength = sizeof(DEFAULT_LOG_FILE_NAME) + sizeof(UNICODE_NULL);
//	fileName.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool,
//	fileName.MaximumLength, FSI_POOL_TAG);

	fileName.MaximumLength = sizeof(FileNameBuffer);
	fileName.Buffer = (PWSTR)&FileNameBuffer;

	if (!fileName.Buffer)
	{
		isLogging = FALSE;
		return FALSE;
	}

	RtlZeroMemory(fileName.Buffer, fileName.MaximumLength);
	status = RtlAppendUnicodeToString(&fileName, (PWSTR)DEFAULT_LOG_FILE_NAME);

	InitializeObjectAttributes(&objectAttributes,
		(PUNICODE_STRING)&fileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateFile(&FileHandle,
		FILE_APPEND_DATA,
		&objectAttributes,
		&IoStatus,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (NT_SUCCESS(status)) {

		Length = (ULONG)strlen((const char *)pBuffer);
		ZwWriteFile(FileHandle, NULL, NULL, NULL, &IoStatus, pBuffer, Length + 1, NULL, NULL);

		ZwClose(FileHandle);
	}

//	if (fileName.Buffer) {
//		ExFreePool(fileName.Buffer);
//	}

	isLogging = FALSE;
//#endif
	return true;
}

// Allocating the common buffer using a DMA Adapter couldn't be mapped into
// user space on XP x64.  Had to use MmAllocateContiguousMemorySpecifyCache().
// Need to look into this later.  FIXME
//#define USE_COMMON_BUFFER_DMA_ADAPTER 1

/*++

Routine Description:

    Create the capture device.  This is the creation dispatch for the
    capture device.

Arguments:

    Device -
        The AVStream device being created.

Return Value:

    Success / Failure

--*/
NTSTATUS CCaptureDevice::DispatchPnpAdd ( IN PKSDEVICE Device )
{

  PAGED_CODE();

  NTSTATUS Status;

  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnpAdd()");

  DECORATED_DEBUG("", "Entry");

  // tag the allocation so I can check for leaks
  CCaptureDevice *CapDevice = new (NonPagedPool, '8roF') CCaptureDevice (Device);

  //
  // Return failure if we couldn't create the device.
  //
  if (!CapDevice) 
  {
    char x[256];
    sprintf_s( x, "CCaptureDevice::DispatchPnpAdd() device creation failed \r\n" );
    FSI_LogMessage( x );
    Status = STATUS_INSUFFICIENT_RESOURCES;
  } 
  else 
  {
      //
      // Add the item to the object bag if we were successful.
      // Whenever the device goes away, the bag is cleaned up and
      // we will be freed.
      //
      // For backwards compatibility with DirectX 8.0, we must grab
      // the device mutex before doing this.  For Windows XP, this is
      // not required, but it is still safe.
      //
    KsAcquireDevice (Device);
    Status = KsAddItemToObjectBag (
        Device->Bag,
        reinterpret_cast <PVOID> (CapDevice),
        reinterpret_cast <PFNKSFREE> (CCaptureDevice::Cleanup)
        );

    KsReleaseDevice (Device);

    if (!NT_SUCCESS (Status)) 
    {
      delete CapDevice;
    } 
    else 
    {
      Device->Context = reinterpret_cast <PVOID> (CapDevice);
    }

  }

  return Status;

}

/*************************************************/

NTSTATUS
CCaptureDevice::
PnpStart (
    IN PCM_RESOURCE_LIST TranslatedResourceList,
    IN PCM_RESOURCE_LIST UntranslatedResourceList
    )

/*++

Routine Description:

    Called at Pnp start.

Arguments:

    TranslatedResourceList -
        The translated resource list from Pnp

    UntranslatedResourceList -
        The untranslated resource list from Pnp

Return Value:

    Success / Failure

--*/

{
	UCHAR        buffer[256] = { 0 };
  int          bytesRead;
  USHORT       VendorID;
  USHORT       DeviceID;
  USHORT       Command;
  USHORT       NewTimer;

  PAGED_CODE();

  DECORATED_DEBUG("", "CCaptureDevice::PnpStart()");

  PPCI_COMMON_CONFIG  pPciConfig = (PPCI_COMMON_CONFIG) buffer;

  NTSTATUS Status = STATUS_SUCCESS;
  
  // 
  // First thing to do is to identify the type of grabber. Do this by
  // reading the Vendor and Device ID's out of the PCI config space
  //
  FsiGetStandardInterface( m_Device->NextDeviceObject, &m_BusInterface);
  bytesRead = m_BusInterface.GetBusData(
         m_BusInterface.Context,
         PCI_WHICHSPACE_CONFIG, //READ
         pPciConfig,
         FIELD_OFFSET(PCI_COMMON_CONFIG, VendorID),
         64);

  VendorID = pPciConfig->VendorID;
  DeviceID = pPciConfig->DeviceID;
  Command  = pPciConfig->Command;
  // and enable memory on the bus
  Command |= 0x03;

	DECORATED_DEBUG("", "Vendor Id = %x, Device Id = %x\r\n", VendorID, DeviceID);

  m_BusInterface.SetBusData(
       m_BusInterface.Context,
       PCI_WHICHSPACE_CONFIG, 
       &Command,
       FIELD_OFFSET(PCI_COMMON_CONFIG, Command),
       sizeof(USHORT));

	DECORATED_DEBUG("", "Original Latency timer = %d\r\n", pPciConfig->LatencyTimer);

  NewTimer = 32;
  m_BusInterface.SetBusData(
       m_BusInterface.Context,
       PCI_WHICHSPACE_CONFIG, 
       &NewTimer,
       FIELD_OFFSET(PCI_COMMON_CONFIG, LatencyTimer),
       sizeof(USHORT));

  bytesRead = m_BusInterface.GetBusData(
         m_BusInterface.Context,
         PCI_WHICHSPACE_CONFIG, //READ
         pPciConfig,
         FIELD_OFFSET(PCI_COMMON_CONFIG, VendorID),
         64);

	DECORATED_DEBUG("", "New Latency timer = %d\r\n", pPciConfig->LatencyTimer);

  //
  // By PnP, it's possible to receive multiple starts without an intervening
  // stop (to reevaluate resources, for example).  Thus, we only perform
  // creations of the device on the initial start and ignore any 
  // subsequent start.  Hardware drivers with resources should evaluate
  // resources and make changes on 2nd start.
  //
  if (!m_Device->Started) 
  {
    m_pGrabber = new (NonPagedPool, 'AroF') CFrameGrabber(DeviceID);

    if (!m_pGrabber) 
    {
      //
      // If we couldn't create the hardware device, fail.
      //
			DECORATED_DEBUG("", "*****  FAILED TO CREATE GRABBER ????? ******\r\n");
      Status = STATUS_INSUFFICIENT_RESOURCES;
      return Status;
    } 
    else 
    {
      Status = KsAddItemToObjectBag (
        m_Device->Bag,
        reinterpret_cast <PVOID> (m_pGrabber),
        //NULL   // Note:: probably should define a cleanup method
        reinterpret_cast <PFNKSFREE> (CCaptureDevice::CleanupGrabber)
        );

      if (!NT_SUCCESS (Status)) 
      {
        delete m_pGrabber;
        return Status;
      }
    }

    Status = m_pGrabber->InitializeResources ( TranslatedResourceList );
    if( ! NT_SUCCESS (Status) )
    {
      FSI_LogMessage("InitializeResources Failed\r\n");
      return Status;
    }
    // store the registry path - it should be:
    //    HKLM\system\CurrentControlSet\Services\ideadrv
    RtlInitUnicodeString( &m_pGrabber->m_RegistryPath, gRegistryPath.Buffer );
    m_pGrabber->m_FrameGrabberType = m_pGrabber->MapBoardIDToType(DeviceID, TRUE);
    m_pGrabber->Initialize(m_DeviceNum);
    m_DeviceNum++;
    m_pGrabber->m_pCaptureDevice = this;
    
    const KSFILTER_DESCRIPTOR *pCaptureFilterDescriptor;
    
    switch( m_pGrabber->m_FrameGrabberType) 
    {
      case HIDEF_ACCUSTREAM_EXPRESS_HDC:
      case HIDEF_ACCUSTREAM_EXPRESS_HDC50:
      case HIDEF_ACCUSTREAM_EXPRESS_HDC75:
        pCaptureFilterDescriptor = &CaptureFilterDescriptorH264;
      break;
      
      default:
        pCaptureFilterDescriptor = &CaptureFilterDescriptor;
        break;
    }
    
    // Create the Filter for the device
    KsAcquireDevice(m_Device);
    Status = KsCreateFilterFactory( m_Device->FunctionalDeviceObject, pCaptureFilterDescriptor,
                                    NULL, NULL, 0, //KSCREATE_ITEM_FREEONSTOP,
                                    NULL, NULL, NULL );
    KsReleaseDevice(m_Device);

	DECORATED_DEBUG("", "KsCreateFilterFactory() returned %x, Device Id = %x\r\n", Status, DeviceID);

    INTERFACE_TYPE InterfaceBuffer;
    ULONG InterfaceLength;
    DEVICE_DESCRIPTION DeviceDescription;
    NTSTATUS IfStatus;

    //
    // Set up DMA...
    //
    IfStatus = IoGetDeviceProperty (
        m_Device->PhysicalDeviceObject,
        DevicePropertyLegacyBusType,
        sizeof (INTERFACE_TYPE),
        &InterfaceBuffer,
        &InterfaceLength
        );

    //
    // Allocate a big enough common buffer to hold lots of descriptors.
    //

    PHYSICAL_ADDRESS LowestAcceptable;
    PHYSICAL_ADDRESS HighestAcceptable;
    PHYSICAL_ADDRESS BoundaryMultiple;
    LowestAcceptable.QuadPart = 0;
    HighestAcceptable.QuadPart = 0xFFFFFFFF;
    BoundaryMultiple.QuadPart = 0;

    pCaptureDescriptors = NULL;
    pCaptureDescriptors = MmAllocateContiguousMemorySpecifyCache( COMMON_BUFFER_SIZE,
                                                            LowestAcceptable,
                                                            HighestAcceptable,
                                                            BoundaryMultiple,
                                                            MmNonCached);
    CaptureDescriptorsPhysAddress.QuadPart = 0;
    CaptureDescriptorsPhysAddress = MmGetPhysicalAddress(pCaptureDescriptors);

    if( pCaptureDescriptors == 0 )
    {
			DECORATED_DEBUG("", "Failed to allocate common buffer\n");
      FSI_LogMessage( "Failed to allocate common buffer\r\n" );
    }
    else
    {
			DECORATED_DEBUG("", "pCaptureDescriptors = 0x%p\n",
          pCaptureDescriptors); 
    }
    
    //
    // Allocate a big enough common buffer to hold lots of descriptors.
    //
    pPreviewDescriptors = NULL;
    pPreviewDescriptors = MmAllocateContiguousMemorySpecifyCache( COMMON_BUFFER_SIZE,
                                                            LowestAcceptable,
                                                            HighestAcceptable,
                                                            BoundaryMultiple,
                                                            MmNonCached);
    PreviewDescriptorsPhysAddress.QuadPart = 0;
    PreviewDescriptorsPhysAddress = MmGetPhysicalAddress(pPreviewDescriptors);

    if( pPreviewDescriptors == 0 )
    {
			DECORATED_DEBUG("", "Failed to allocate preview descriptor buffer\n");
      FSI_LogMessage( "Failed to allocate preview descriptor buffer\r\n" );
    }
    else
    {
			DECORATED_DEBUG("", "pPreviewDescriptors = 0x%p\n",
          pPreviewDescriptors); 
    }
    
    //
    // Allocate a big enough common buffer to hold lots of descriptors.
    //
    pCompressDescriptors = NULL;

		switch (m_pGrabber->m_FrameGrabberType)
		{
			case HIDEF_ACCUSTREAM_EXPRESS_HDC:
			case HIDEF_ACCUSTREAM_EXPRESS_HDC50:
			case HIDEF_ACCUSTREAM_EXPRESS_HDC75:
				pCompressDescriptors = MmAllocateContiguousMemorySpecifyCache(COMMON_BUFFER_SIZE,
					LowestAcceptable,
					HighestAcceptable,
					BoundaryMultiple,
					MmNonCached);
				CompressDescriptorsPhysAddress.QuadPart = 0;
				CompressDescriptorsPhysAddress = MmGetPhysicalAddress(pCompressDescriptors);

				if (pCompressDescriptors == 0)
				{
					DECORATED_DEBUG("", "Failed to allocate compress descriptor buffer\n");
				}
				else
				{
					DECORATED_DEBUG("", "pCompressDescriptors = 0x%p\n", pCompressDescriptors);
				}

				break;

			default:
				break;
		}


  // now create and register a dma adapter to be used for all other dma operations
    memset( &DeviceDescription, 0, sizeof(DeviceDescription) );
    DeviceDescription.Version = DEVICE_DESCRIPTION_VERSION;
    DeviceDescription.DmaChannel = ((ULONG) ~0);
    DeviceDescription.InterfaceType = PCIBus;
    DeviceDescription.DmaWidth = Width32Bits;
    DeviceDescription.DmaSpeed = Compatible;
    DeviceDescription.ScatterGather = TRUE;
    DeviceDescription.Master = TRUE;
    DeviceDescription.Dma32BitAddresses = TRUE;
    DeviceDescription.Dma64BitAddresses = TRUE;  // allow buffer to be in above 4gb
    DeviceDescription.AutoInitialize = FALSE;
    DeviceDescription.MaximumLength = (ULONG)-1;

    //
    // Get a DMA adapter object from the system.
    //
    m_DmaAdapterObject = IoGetDmaAdapter (
        m_Device->PhysicalDeviceObject,
        &DeviceDescription,
        &m_NumberOfMapRegisters
        );

    if (!m_DmaAdapterObject) 
    {
      Status = STATUS_UNSUCCESSFUL;
    }
    else
    {

#ifndef _WIN64
      // Should be using RegisterAdapterObjectEx for 64 bit - FIXME  
      KsDeviceRegisterAdapterObject (
          m_Device,
          m_DmaAdapterObject,
          (8 << 20),                     // maximum - arbitrary, but set to 8M
          sizeof (KSMAPPING)
          );
#else
      PUNKNOWN DeviceUnk = KsDeviceGetOuterUnknown(m_Device);

      // Register the DMA adapter with AVStream
      IKsDeviceFunctions *DeviceFunctions;
      Status = DeviceUnk->QueryInterface(
                          __uuidof (IKsDeviceFunctions),
                          (PVOID *)&DeviceFunctions
                        );

      // Conditionally, call IksDeviceFunctions::RegisterAdapterObjectEx, 
      // which will not break downlevel load compatibility.
      // If QueryInterface call fails, call KsDeviceRegisterAdapterObject to
      // preserve downlevel load compatibility.
      if (NT_SUCCESS (Status)) {
				DECORATED_DEBUG("", "Calling RegisterAdapterObjectEx()\n");
        DeviceFunctions->RegisterAdapterObjectEx(
                           m_DmaAdapterObject,
                           &DeviceDescription,
                           m_NumberOfMapRegisters,
                           (8 << 20), // maximum - arbitrary, but set to 8MB
                           sizeof (KSMAPPING)
                         );
        DeviceFunctions->Release();
      }
      else
      {
				DECORATED_DEBUG("", "Calling KsDeviceRegisterAdapterObject()\n");
        KsDeviceRegisterAdapterObject (
          m_Device,
          m_DmaAdapterObject,
          (8 << 20), // maximum - arbitrary, but set to 8MB
          sizeof (KSMAPPING)
        );
      }
#endif
    }

    //
    // Allocate a mailbox for IdeaProxy.
    //
    pMailBox = NULL;
    pMailBox = (PMAILBOX)MmAllocateContiguousMemorySpecifyCache( MAILBOX_SIZE,
                                                       LowestAcceptable,
                                                       HighestAcceptable,
                                                       BoundaryMultiple,
                                                       MmNonCached);

    if( pMailBox == 0 )
    {
			DECORATED_DEBUG("", "Failed to allocate MailBox buffer\r\n");
      FSI_LogMessage( "Failed to allocate MailBox buffer\r\n" );
    }
    else
    {
			DECORATED_DEBUG("", "pMailBox = 0x%p\r\n", pMailBox);
      RtlZeroMemory(pMailBox, MAILBOX_SIZE); 
    }
  }
  else
  {
		DECORATED_DEBUG("", "Device was already started. \r\n");
  }
  
  for(int n = 0; n < NUM_DRIVER_EVENTS; n++)
    m_hDriverEvents[n] = 0;

  m_nProcessCount = 0;
  
  return Status;

}

/*************************************************/
void CCaptureDevice::SavePCIConfig()
/*++

Routine Description:

    Save the Express board's pci config space, this will
    get destroyed by re-loading the FPGA, so it will need
    to be restored.

Arguments:
    None

Return Value:
    None
--*/
{
  PAGED_CODE();

  int bytesRead;

  // read all the bytes out of the PCI config space at once.
  bytesRead = m_BusInterface.GetBusData(
         m_BusInterface.Context,
         PCI_WHICHSPACE_CONFIG, //READ
         PCIConfig,
         FIELD_OFFSET(PCI_COMMON_CONFIG, VendorID),
         64);
}

/*************************************************/
void CCaptureDevice::RestorePCIConfig()
/*++

Routine Description:

    Restore the Express board's pci config space, this will
    get destroyed by re-loading the FPGA, so it will need
    to be restored.

Arguments:
    None

Return Value:
    None
--*/
{
  PAGED_CODE();

  int bytesWritten;
  USHORT Command = 0;

  bytesWritten = m_BusInterface.SetBusData(
       m_BusInterface.Context,
       PCI_WHICHSPACE_CONFIG, 
       PCIConfig,
       FIELD_OFFSET(PCI_COMMON_CONFIG, VendorID),
       64 );


  // and enable memory on the bus
  Command |= 0x03;

  m_BusInterface.SetBusData(
       m_BusInterface.Context,
       PCI_WHICHSPACE_CONFIG, 
       &Command,
       FIELD_OFFSET(PCI_COMMON_CONFIG, Command),
       sizeof(USHORT));

}

/*************************************************/

NTSTATUS CCaptureDevice::PnpQueryStop()

/*++

Routine Description:

This is the pnp query stop dispatch for the capture device.

Arguments:

None

Return Value:

NTSTATUS (success for OK to stop and unsuccessful for not OK)

--*/

{
	PAGED_CODE();

	DECORATED_DEBUG("", "Entry");

	// need to return Success or unsuccessful
	return STATUS_SUCCESS;
}

/*************************************************/

void CCaptureDevice::PnpCancelStop()

/*++

Routine Description:

This is the pnp cancel stop dispatch for the capture device.

Arguments:

None

Return Value:

None

--*/

{
	PAGED_CODE();

	DECORATED_DEBUG("", "Entry");

}

/*************************************************/

void CCaptureDevice::PnpStop ()

/*++

Routine Description:

    This is the pnp stop dispatch for the capture device.  It releases any
    adapter object previously allocated by IoGetDmaAdapter during Pnp Start.

Arguments:

    None

Return Value:

    None

--*/

{
  PAGED_CODE();

  DECORATED_DEBUG("", "Entry");

  //DECORATED_DEBUG("", "In PnPStop, - PnPStopType = %d\r\n", (int)m_PnPStopType);

  // disable any interrupts
  if( m_pGrabber )
  {
    m_pGrabber->m_pBoardRegisters->dwICS = 0;
    m_pGrabber->m_bAlteraInitialized = FALSE;
    m_pGrabber->Uninitialize(m_PnPStopType);
  }
  
  if (m_DmaAdapterObject) 
  {
    //
    // Return the DMA adapter back to the system.
    //
    m_DmaAdapterObject->DmaOperations->PutDmaAdapter (m_DmaAdapterObject);

    m_DmaAdapterObject = NULL;
  }

#ifdef USE_COMMON_BUFFER_DMA_ADAPTER
  if (m_DmaAdapterObjectForCaptureDescriptors) 
  {
    // Return the DMA CaptureDescriptors back to the system.
    m_DmaAdapterObjectForCaptureDescriptors->DmaOperations->FreeCaptureDescriptors (
        m_DmaAdapterObjectForCaptureDescriptors, COMMON_BUFFER_SIZE, CaptureDescriptorsPhysAddress, pCaptureDescriptors, FALSE );

    // Return the DMA adapter back to the system.
    //
    m_DmaAdapterObjectForCaptureDescriptors->DmaOperations->PutDmaAdapter (m_DmaAdapterObjectForCaptureDescriptors);

    m_DmaAdapterObjectForCaptureDescriptors = NULL;
  }
#else
	if (pCaptureDescriptors != NULL)
	{
		MmFreeContiguousMemorySpecifyCache(pCaptureDescriptors, COMMON_BUFFER_SIZE, MmNonCached);
		pCaptureDescriptors = 0;
	}

	if (pPreviewDescriptors != NULL)
	{
		MmFreeContiguousMemorySpecifyCache(pPreviewDescriptors, COMMON_BUFFER_SIZE, MmNonCached);
		pPreviewDescriptors = 0;
	}

	if (pCompressDescriptors != NULL)
	{
		MmFreeContiguousMemorySpecifyCache(pCompressDescriptors, COMMON_BUFFER_SIZE, MmNonCached);
		pCompressDescriptors = 0;
	}
		
	if (pMailBox != NULL)
	{
		MmFreeContiguousMemorySpecifyCache(pMailBox, MAILBOX_SIZE, MmNonCached);
		pMailBox = 0;
	}
#endif

  if( m_DeviceNum )
    m_DeviceNum--;

  // reset the flag so next stop will be normal unless notified otherwise through SURPRISE PNP EVENT
  m_PnPStopType = NORMAL_PNP_STOP;
}

/*************************************************/

NTSTATUS CCaptureDevice::PnpQueryRemove()

/*++

Routine Description:

This is the pnp query remove dispatch for the capture device.

Arguments:

None

Return Value:

NTSTATUS

--*/

{
	PAGED_CODE();

	DECORATED_DEBUG("", "Entry");

	// need to return Success or unsuccessful
	return STATUS_SUCCESS;
}

/*************************************************/

void CCaptureDevice::PnpCancelRemove()

/*++

Routine Description:

This is the pnp cancel remove dispatch for the capture device.

Arguments:

None

Return Value:

None

--*/

{
	PAGED_CODE();

	DECORATED_DEBUG("", "Entry");

}

/*************************************************/

void CCaptureDevice::PnpRemove()

/*++

Routine Description:

This is the pnp remove dispatch for the capture device.

Arguments:

None

Return Value:

None

--*/

{
	PAGED_CODE();

	DECORATED_DEBUG("", "Entry");
}

/*************************************************/
NTSTATUS CCaptureDevice::AcquireHardwareResources (
    IN PKS_VIDEOINFO VideoInfoHeader
    )

/*++

Routine Description:

    Acquire hardware resources for the capture hardware.  If the 
    resources are already acquired, this will return an error.
    The hardware configuration must be passed as a VideoInfoHeader.

Arguments:


    VideoInfoHeader -
        Information about the capture stream.  This **MUST** remain
        stable until the caller releases hardware resources.  Note
        that this could also be guaranteed by bagging it in the device
        object bag as well.

Return Value:

    Success / Failure

--*/

{

  PAGED_CODE();

  NTSTATUS Status = STATUS_SUCCESS;

  DECORATED_DEBUG( m_pGrabber->m_szSerialNo, "Entry.");

  //
  // If we're the first pin to go into acquire (remember we can have
  // a filter in another graph going simultaneously), grab the resources.
  //
  if(InterlockedCompareExchange(&m_PinsWithResources, 1, 0) == 0) 
  {
    m_pVideoInfoHeader = VideoInfoHeader;

    // Double check that the format sent in is valid.
    if ( !((m_pVideoInfoHeader->bmiHeader.biBitCount == 24 &&
            m_pVideoInfoHeader->bmiHeader.biCompression == KS_BI_RGB) || 
           (m_pVideoInfoHeader->bmiHeader.biBitCount == 16 &&
            m_pVideoInfoHeader->bmiHeader.biCompression == FOURCC_YUY2) ))
    {
			DECORATED_DEBUG("", "returning INVALID_PARAMETER\r\n");
      Status = STATUS_INVALID_PARAMETER;
    }


    if (!NT_SUCCESS (Status)) 
    {
      //
      // If anything failed in here, we release the resources we've
      // acquired.
      //
			DECORATED_DEBUG("", "Bad Return - Releasing\r\n");
      ReleaseHardwareResources ();
    }
  
  } 
  else 
  {
		DECORATED_DEBUG("", "returning SHARING_VIOLATION\r\n");
    Status = STATUS_SHARING_VIOLATION;
  }

  return Status;

}

/*************************************************/
void CCaptureDevice::ReleaseHardwareResources ( )

/*++

Routine Description:

    Release hardware resources.  This should only be called by
    an object which has acquired them.

Arguments:

    None

Return Value:

    None

--*/

{
  PAGED_CODE();

  DECORATED_DEBUG( m_pGrabber->m_szSerialNo, "Entry");

  // only release resources if we have a lock on them
  // and at the same time, release the lock
  if(InterlockedCompareExchange(&m_PinsWithResources, 0, 1) == 1)
  {
    m_pVideoInfoHeader = NULL;

    // tell the grabber to clean up any allocated buffers
//    m_pGrabber->DeleteAllocateBuffers();

  }
}

/*************************************************/

NTSTATUS CCaptureDevice::Start()

/*++

Routine Description:

    Start the capture device based on the video info header we were told
    about when resources were acquired.

Arguments:

    None

Return Value:

    Success / Failure

--*/

{
  PAGED_CODE();

  m_LastMappingsCompleted = 0;

  if( m_pVideoInfoHeader == 0 )
  {
    DECORATED_DEBUG(m_pGrabber->m_szSerialNo, "m_pVideoInfoHeader == 0,  returning STATUS_INSUFFICIENT_RESOURCES");

    return STATUS_INSUFFICIENT_RESOURCES; 
  }
	else
		DECORATED_DEBUG( m_pGrabber->m_szSerialNo, "CCaptureDevice::Start()");

  return m_pGrabber->StartCapture( m_pVideoInfoHeader );
}

/*************************************************/

NTSTATUS CCaptureDevice::Pause (IN BOOLEAN Pausing )

/*++

Routine Description:

    Pause or unpause the hardware streaming.  This is an effective start
    or stop without resetting counters and formats.  Note that this can
    only be called to transition from started->paused->started.  Calling
    this without starting the hardware with Start() does nothing.

Arguments:

    Pausing -
        An indicatation of whether we are pausing or unpausing

        TRUE -
            Pause the hardware simulation

        FALSE -
            Unpause the hardware simulation

Return Value:

    Success / Failure

--*/

{

  PAGED_CODE();

  DECORATED_DEBUG( m_pGrabber->m_szSerialNo, "Entry");

// pause the FrameGrabber, this will shut down any
// active DMA operations.
  return m_pGrabber->PauseCapture(Pausing);

}

/*************************************************/
NTSTATUS CCaptureDevice::Stop( )

/*++

Routine Description:

    Stop the capture device.

Arguments:

    None

Return Value:

    Success / Failure

--*/

{
  PAGED_CODE();

  DECORATED_DEBUG( m_pGrabber->m_szSerialNo, "Entry");

  return m_pGrabber->StopCapture();
}



/*************************************************************************

    LOCKED CODE

**************************************************************************/

#ifdef ALLOC_PRAGMA
#pragma code_seg()
#endif // ALLOC_PRAGMA



/**************************************************************************

    DESCRIPTOR AND DISPATCH LAYOUT

**************************************************************************/

//
// CaptureFilterDescriptor:
//
// The filter descriptor for the capture device.
DEFINE_KSFILTER_DESCRIPTOR_TABLE (FilterDescriptors)
{ 
  &CaptureFilterDescriptor
};

//
// CaptureDeviceDispatch:
//
// This is the dispatch table for the capture device.  Plug and play
// notifications as well as power management notifications are dispatched
// through this table.
//
const KSDEVICE_DISPATCH CaptureDeviceDispatch =
{
  CCaptureDevice::DispatchPnpAdd,				// Pnp Add Device
  CCaptureDevice::DispatchPnpStart,				// Pnp Start

  NULL, //CCaptureDevice::DispatchPnPPostStart,			// Post-Start

  CCaptureDevice::DispatchPnpQueryStop,			// Pnp Query Stop
  NULL, // CCaptureDevice::DispatchPnpCancelStop,		// Pnp Cancel Stop
  CCaptureDevice::DispatchPnpStop,				// Pnp Stop
  CCaptureDevice::DispatchPnpQueryRemove,		// Pnp Query Remove
  NULL, //CCaptureDevice::DispatchPnpCancelRemove,		// Pnp Cancel Remove
  CCaptureDevice::DispatchPnpRemove,			// Pnp Remove

  NULL, //CCaptureDevice::DispatchPnPQueryCaps,			// Pnp Query Capabilities

  NULL, //CCaptureDevice::DispatchPnpSurpriseRemoval,	// Pnp Surprise Removal

  NULL, //CCaptureDevice::DispatchPnPQueryPower,		// Power Query Power
  NULL, //CCaptureDevice::DispatchPnPSetPower,			// Power Set Power
  NULL //CCaptureDevice::DispatchPnPQueryInterface		// Pnp Query Interface
};

//
// CaptureDeviceDescriptor:
//
// This is the device descriptor for the capture device.  It points to the
// dispatch table and contains a list of filter descriptors that describe
// filter-types that this device supports.  Note that the filter-descriptors
// can be created dynamically and the factories created via 
// KsCreateFilterFactory as well.  
//
#if 0
const KSDEVICE_DESCRIPTOR CaptureDeviceDescriptor =
{
  &CaptureDeviceDispatch,
  SIZEOF_ARRAY (FilterDescriptors),
  FilterDescriptors,
  KSDEVICE_DESCRIPTOR_VERSION
};
#else
const KSDEVICE_DESCRIPTOR CaptureDeviceDescriptor =
{
  &CaptureDeviceDispatch,
  0,
  NULL,
  KSDEVICE_DESCRIPTOR_VERSION
};
#endif

/**************************************************************************

    INITIALIZATION CODE

**************************************************************************/

static char RegistryPathBuffer[1024];

EXTERN_C_START
DRIVER_INITIALIZE DriverEntry;
EXTERN_C_END

_Use_decl_annotations_
NTSTATUS
  DriverEntry (
    IN PDRIVER_OBJECT DriverObject, 
    IN PUNICODE_STRING RegistryPath
    )

/*++

Routine Description:

    Driver entry point.  Pass off control to the AVStream initialization
    function (KsInitializeDriver) and return the status code from it.

Arguments:

    DriverObject -
        The WDM driver object for our driver

    RegistryPath -
        The registry path for our registry info

Return Value:

    As from KsInitializeDriver

--*/

{
  NTSTATUS status;
  char x[256];

  // Single Binary Opt-In: POOL_NX_OPTIN for proper non-paged pool allocations
  // on all versions of Windows.
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	  //
  // Simply pass the device descriptor and parameters off to AVStream
  // to initialize us.  This will cause filter factories to be set up
  // at add & start.  Everything is done based on the descriptors passed
  // here.
  //

  status = KsInitializeDriver (
          DriverObject,
          RegistryPath,
          &CaptureDeviceDescriptor
          );

  {

		char tstring[256];
    ANSI_STRING asString;
    int nBytes;

		DECORATED_DEBUG("", "Status from initialize = %u\r\n", status );
    asString.Length = (USHORT)RtlUnicodeStringToAnsiSize(RegistryPath);
    asString.MaximumLength  = 256;
    asString.Buffer = tstring;

    RtlUnicodeStringToAnsiString( &asString, RegistryPath, false );
		DECORATED_DEBUG("", "RegistryPath = %s\r\n", tstring );
 
    asString.Length = (USHORT)RtlUnicodeStringToAnsiSize(DriverObject->HardwareDatabase);
    RtlUnicodeStringToAnsiString( &asString, DriverObject->HardwareDatabase, false );
		DECORATED_DEBUG("", "HardwareDatabase = %s\r\n", tstring );
  }

  // Store the registry path in a global
  gRegistryPath.MaximumLength = RegistryPath->Length + sizeof(UNICODE_NULL);
  gRegistryPath.Length = RegistryPath->Length;
  //gRegistryPath.Buffer = (PWSTR)ExAllocatePoolWithTag (
  //                                     PagedPool,
  //                                     gRegistryPath.MaximumLength,
  //                                     FSI_POOL_TAG);	
  gRegistryPath.Buffer = (PWSTR)&RegistryPathBuffer;

  RtlCopyUnicodeString( &gRegistryPath, RegistryPath );

  m_OrigDispatchControl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
  m_OrigDispatchCreate  = DriverObject->MajorFunction[IRP_MJ_CREATE];
  m_OrigDispatchClose   = DriverObject->MajorFunction[IRP_MJ_CLOSE];
  m_OrigDispatchCleanup = DriverObject->MajorFunction[IRP_MJ_CLEANUP];

  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CCaptureDevice::DispatchControl;
  DriverObject->MajorFunction[IRP_MJ_CREATE]         = CCaptureDevice::DispatchCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE]          = CCaptureDevice::DispatchClose;
  DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = CCaptureDevice::DispatchCleanup;

  m_DeviceNum = 0;

  return status;
}


_Use_decl_annotations_
NTSTATUS CCaptureDevice::DispatchCreate(
  IN  PDEVICE_OBJECT  DeviceObject,
  IN  PIRP            Irp
)
{
  PKSDEVICE pObject = KsGetDeviceForDeviceObject(DeviceObject);

  if( pObject == NULL )
  {
    DECORATED_DEBUG("", "pObject is NULL, returning STATUS_INVALID_PARAMETER");

    return STATUS_INVALID_PARAMETER;
  }

  CCaptureDevice *pCapDevice = reinterpret_cast<CCaptureDevice *>(pObject->Context);
  
  HANDLE hProcessID = PsGetCurrentProcessId();
  int nEntry = 0;

  if(pCapDevice->m_nProcessCount == 0)
  {
    pCapDevice->m_ProcessList[0].hID = hProcessID;
    pCapDevice->m_ProcessList[0].nRefCount = 1;
    pCapDevice->m_nProcessCount = 1;
  }
  else
  {
    // Find the process ID
    for(nEntry = 0; nEntry < pCapDevice->m_nProcessCount; nEntry++)
    {
      if(pCapDevice->m_ProcessList[nEntry].hID == hProcessID)
      {
        pCapDevice->m_ProcessList[nEntry].nRefCount++;
        break;
      }
    }
  
    // Add the process ID to the end if it wasn't in the list
    if(nEntry == pCapDevice->m_nProcessCount)
    {
      pCapDevice->m_ProcessList[nEntry].hID = hProcessID;
      pCapDevice->m_ProcessList[nEntry].nRefCount = 1;
      pCapDevice->m_nProcessCount++;
    }
  }

  DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "RefCount = %d -> %d, ProcCount = %d",
                  pCapDevice->m_ProcessList[nEntry].nRefCount - 1,
                  pCapDevice->m_ProcessList[nEntry].nRefCount,
                  pCapDevice->m_nProcessCount);

  if(m_OrigDispatchCreate)
    return m_OrigDispatchCreate(DeviceObject, Irp);
  else
  {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
  }
}


/*************************************************************/
_Use_decl_annotations_
NTSTATUS CCaptureDevice::DispatchCleanup(
  IN  PDEVICE_OBJECT  DeviceObject,
  IN  PIRP            Irp
)
{
  BOOL bDecrementRefCount = FALSE;
  PKSDEVICE pObject = KsGetDeviceForDeviceObject(DeviceObject);

  if( pObject == NULL )
  {
    DECORATED_DEBUG("", "pObject is NULL, returning STATUS_INVALID_PARAMETER");
    return STATUS_INVALID_PARAMETER;
  }

  CCaptureDevice *pCapDevice = reinterpret_cast<CCaptureDevice *>(pObject->Context);
  HANDLE hProcessID = PsGetCurrentProcessId();

  PEPROCESS pEProcess = NULL;
  int nEntry;
  BOOL bProcessInList = FALSE;
    
  // Find the process ID in our list
  for(nEntry = 0; nEntry < pCapDevice->m_nProcessCount; nEntry++)
  {
    if(pCapDevice->m_ProcessList[nEntry].hID == hProcessID)
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                      "RefCount = %d -> %d, ProcCount = %d",
                      pCapDevice->m_ProcessList[nEntry].nRefCount,
                      pCapDevice->m_ProcessList[nEntry].nRefCount - 1,
                      pCapDevice->m_nProcessCount);

      bProcessInList = TRUE;
      break;
    }
  }
  
  if(!bProcessInList)
  {
    DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                    "RefCount = Not In List, ProcCount = %d",
                    pCapDevice->m_nProcessCount);
  }

  if(pCapDevice->m_pGrabber->m_IsClaimed)
  {
    if(pCapDevice->m_pGrabber->m_hClaimingProcessID != hProcessID)
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                      "Calling process %p is not claiming process %p",
                      hProcessID,
                      pCapDevice->m_pGrabber->m_hClaimingProcessID);

      // Claiming process exists?
      if(PsLookupProcessByProcessId( pCapDevice->m_pGrabber->m_hClaimingProcessID, &pEProcess) == STATUS_INVALID_PARAMETER)
      {
        DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                        "Claiming process %p not found.",
						pCapDevice->m_pGrabber->m_hClaimingProcessID);
        pCapDevice->UnClaim();
      }
      else
      {
        LARGE_INTEGER timeout;
        timeout.QuadPart = 0x0;

        NTSTATUS status = KeWaitForSingleObject( pEProcess, Executive, KernelMode, FALSE, &timeout);
		
        ObDereferenceObject(pEProcess);
        
        if(status != STATUS_TIMEOUT)
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "Claiming process %p has exited.",
                          pCapDevice->m_pGrabber->m_hClaimingProcessID);
          pCapDevice->UnClaim();
        }
        else
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "Claiming process %p is still running.",
                          pCapDevice->m_pGrabber->m_hClaimingProcessID);

          // Process not in the list - Must be a debugger.
          if(!bProcessInList)
          {
            DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                            "Calling process must be Debugger, release claim.");
            pCapDevice->UnClaim();
          }
        }
      }
    }
    else
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                      "Calling process %p is claiming process %p.",
                      hProcessID,
                      pCapDevice->m_pGrabber->m_hClaimingProcessID);
    
      if(bProcessInList)
      {
        if(pCapDevice->m_ProcessList[nEntry].nRefCount == 1)
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "Calling process RefCount going to 0, release claim.");
          pCapDevice->UnClaim();
        }
      }
    }
  }
    
  if(bProcessInList)
  {
    pCapDevice->m_ProcessList[nEntry].nRefCount--;

    if(pCapDevice->m_ProcessList[nEntry].nRefCount == 0)
    {
      if(--pCapDevice->m_nProcessCount < 0)
        pCapDevice->m_nProcessCount = 0;

      // Move the entries up in the list
      for( ; nEntry < pCapDevice->m_nProcessCount; nEntry++)
        pCapDevice->m_ProcessList[nEntry] = pCapDevice->m_ProcessList[nEntry + 1];
    }
  }  

  if(m_OrigDispatchCleanup)
    return m_OrigDispatchCleanup(DeviceObject, Irp);
  else
  {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
  }
}


/*************************************************************/
_Use_decl_annotations_
NTSTATUS CCaptureDevice::DispatchClose(
  IN  PDEVICE_OBJECT  DeviceObject,
  IN  PIRP            Irp
)
{
  PKSDEVICE pObject = KsGetDeviceForDeviceObject(DeviceObject);

  if( pObject == NULL )
  {
    DECORATED_DEBUG("", "pObject is NULL, returning STATUS_INVALID_PARAMETER");

    return STATUS_INVALID_PARAMETER;
  }

  CCaptureDevice *pCapDevice = reinterpret_cast<CCaptureDevice *>(pObject->Context);

  HANDLE hProcessID = PsGetCurrentProcessId();

  int  nEntry;
  BOOL bProcessInList = FALSE;
   
  // Find the process ID in our list
  for(nEntry = 0; nEntry < pCapDevice->m_nProcessCount; nEntry++)
  {
    if(pCapDevice->m_ProcessList[nEntry].hID == hProcessID)
    {
      bProcessInList = TRUE;
      break;
    }
  }

  if(bProcessInList)
  {
    DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                    "RefCount = %d, ProcCount = %d",
                    pCapDevice->m_ProcessList[nEntry].nRefCount,
                    pCapDevice->m_nProcessCount);
  }
  else
  {
    DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "Process not found in list.");
  }
  
  if(m_OrigDispatchClose)
    return m_OrigDispatchClose(DeviceObject, Irp);
  else
  {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
  }
}


/*************************************************************/
_Use_decl_annotations_
NTSTATUS CCaptureDevice::DispatchControl(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    )
/*++

Routine Description:
    Handle an IOCTL generated by the native library

Arguments:

Return Value:

--*/
{
  PIO_STACK_LOCATION      irpStack;
  NTSTATUS                status = STATUS_SUCCESS;
  int InLen;
  int OutLen;

  // kjm - TEST
  //if (1)
//	return STATUS_SUCCESS;

  // Error-check the input parameters.
  if( DeviceObject == NULL )
    return STATUS_INVALID_PARAMETER;

  PKSDEVICE pObject = KsGetDeviceForDeviceObject(DeviceObject);

  if( pObject == NULL )
  {
    DECORATED_DEBUG("", "pObject == NULL - Returning STATUS_INVALID_PARAMETER");
    return STATUS_INVALID_PARAMETER;
  }
  
  CCaptureDevice *pCapDevice = reinterpret_cast<CCaptureDevice *>(pObject->Context);
  HANDLE hProcessID = PsGetCurrentProcessId();

  irpStack = IoGetCurrentIrpStackLocation (Irp);

  if( irpStack == 0 )
  {
    DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "irpStack == 0 - Returning STATUS_SUCCESS");
    Irp->IoStatus.Status = status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    return status;
  }

#if 0
  {
    if(irpStack->Parameters.DeviceIoControl.IoControlCode != 0x2f0003) // Happens all the time!
    {
			DECORATED_DEBUG("", "IOCTL = %x \r\n", irpStack->Parameters.DeviceIoControl.IoControlCode);
  }
#endif

  DWORD IoControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
  
  switch (IoControlCode)
  {
    case IOCTL_HIDEF_INITIALIZE:
    {
      INITIALIZE_INFO *pInitInfo = (INITIALIZE_INFO *)Irp->AssociatedIrp.SystemBuffer;
      
      // Suspend interrupt processing while loading the altera
      if( pInitInfo->dwReason == INITIALIZE_ALTERA_LOADING )
      {
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "IOCTL_HIDEF_INITIALIZE - INITIALIZE_ALTERA_LOADING.");
        }

        pCapDevice->m_pGrabber->m_bAlteraInitialized = FALSE;
      }

      // Its now ok to accept interrupts
      if( pInitInfo->dwReason == INITIALIZE_ALTERA_LOADED )
      {
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "IOCTL_HIDEF_INITIALIZE - INITIALIZE_ALTERA_LOADED.");
        }
        // clear all events, no enables
        pCapDevice->m_pGrabber->m_pBoardRegisters->dwICS = 0x00FF00FF;
        // Recheck part #
        pCapDevice->m_pGrabber->m_FrameGrabberType = pCapDevice->m_pGrabber->MapBoardIDToType(pCapDevice->m_pGrabber->m_DeviceID, FALSE);
        pCapDevice->m_pGrabber->m_bAlteraInitialized = TRUE;
      }
      
      Irp->IoStatus.Information = 0;
      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;

    } break;

    case IOCTL_HIDEF_REPORT:
	{
		DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
			"Enter IOCTL_HIDEF_REPORT.");

		DWORD dwInfo = 1;
		HD_sReport *pInReport;
		HD_sReport *pOutReport;

		pInReport = reinterpret_cast<HD_sReport *>(Irp->AssociatedIrp.SystemBuffer);
		InLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
		OutLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

		if (OutLen)
		{
			pOutReport = reinterpret_cast<HD_sReport *>(Irp->AssociatedIrp.SystemBuffer);
			pCapDevice->DoReport(pInReport, (short)InLen, pOutReport, (short)OutLen, &dwInfo);
			DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
				"Exit IOCTL_HIDEF_REPORT. # boards = %d", pOutReport->nBrdCount);
		}
		else
		{
			pOutReport = 0;
			DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
				"Exit IOCTL_HIDEF_REPORT. pOutReport not correct");
		}

      Irp->IoStatus.Information = dwInfo;
      IoCompleteRequest (Irp, IO_NO_INCREMENT);


      return STATUS_SUCCESS;
    }
    break;

    case IOCTL_HIDEF_CLAIM:
    {
      DWORD dwInfo;

      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_CLAIM.");

      InLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
      OutLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
      Irp->IoStatus.Information = OutLen;
      pCapDevice->Claim( (HDDRV_IO_CLAIM *) Irp->AssociatedIrp.SystemBuffer,
            (short) InLen,
            (HDDRV_IO_CLAIM *) Irp->AssociatedIrp.SystemBuffer,
            (short) OutLen,
            &dwInfo);

      Irp->IoStatus.Information = sizeof( HDDRV_IO_CLAIM );
      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }
    
    case IOCTL_HIDEF_UNCLAIM:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_UNCLAIM.");

      DWORD dwInfo;
      OutLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
      pCapDevice->UnClaim();
      Irp->IoStatus.Information = OutLen;
      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }

    case IOCTL_HIDEF_BASEPTRS:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_BASEPTRS.");

      BASEPTRINFO *pInfo = reinterpret_cast<BASEPTRINFO *>(Irp->AssociatedIrp.SystemBuffer);
      InLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
      OutLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
      pCapDevice->GetBasePointers(pInfo);
      Irp->IoStatus.Information = OutLen;

      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }

    case IOCTL_HIDEF_LOCK_DMA_BUFFER:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_LOCK_DMA_BUFFER.");

      EXECUTION_CONTEXT EContext;
      NTSTATUS nStat;
      InLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
      OutLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

      I_SCATTER_LIST *pScatterList = (I_SCATTER_LIST *)Irp->AssociatedIrp.SystemBuffer;
      void *pBuffer              = (void *)pScatterList->pBuffer;
      ULONG dwNumPages           = ADDRESS_AND_SIZE_TO_SPAN_PAGES( pBuffer, pScatterList->dwBufferSize );
      unsigned char  *pbyBuffer;
      PMDL pMdl;
      int  i;
      PVOID pvUserAddress;
      PVOID MappedSystemVa;
      int  iTimeout = 0;
      int nTries = 20;   // 1ms
      int nTry = 0;

        // Have to keep track of what process locks the buffer, so Cleanup wont destroy the entries
      pScatterList->dwMemHandle = MAXDWORD32;   // signal an error

      pMdl = pCapDevice->MyIoAllocateMdl(pBuffer, (ULONG)pScatterList->dwBufferSize, FALSE, FALSE, NULL);
            
      if( (PMDL) 0 == pMdl ) 
      {
        Irp->IoStatus.Information  = sizeof(I_SCATTER_LIST);
        pScatterList->dwMemHandle = MAXDWORD32;

		DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
          "Error on IoAllocateMdl() - cannot allocate MDL for addr: 0x%I64x, size: %d\r\n",
          (__int64)pBuffer, pScatterList->dwBufferSize);
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
      }
      
      for(nTry = 0; nTry < nTries; nTry++)
      {
        __try
        { 
          MmProbeAndLockPages(pMdl, UserMode, IoModifyAccess);
          break;
        }
        __except( EXCEPTION_EXECUTE_HANDLER )
        { 
          NTSTATUS Status = GetExceptionCode();

		  DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
            "Exception 0x%x on MmProbeAndLockPages(), addr 0x%p, size %d, Try %d\r\n",
            Status, pBuffer, pScatterList->dwBufferSize, nTry);
        }

        KeStallExecutionProcessor(50);
      }

      if(nTry >= nTries)
      {
        IoFreeMdl( pMdl );
        *(ULONG *)Irp->AssociatedIrp.SystemBuffer =  0L;
        Irp->IoStatus.Information  =  sizeof(I_SCATTER_LIST);
        pScatterList->dwMemHandle = MAXDWORD32;

		DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
          "MmProbeAndLockPages() failed %d times in a row, give up.\r\n", nTry);
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
      }
                    
      MappedSystemVa = MmGetMdlVirtualAddress(pMdl);
      dwNumPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES( MappedSystemVa, pScatterList->dwBufferSize );

      KIRQL oldirql;
      ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
      KeRaiseIrql(DISPATCH_LEVEL, &oldirql);

      pScatterList->dwNumberListEntries = 0;
      EContext.pIScatterList = pScatterList;
      EContext.pSysScatterGatherList = 0;

      for(nTry = 0; nTry < nTries; nTry++)
      {
        // Obtain the scatter/gather list for the locked buffer
        nStat = pCapDevice->m_DmaAdapterObject->DmaOperations->GetScatterGatherList(
          pCapDevice->m_DmaAdapterObject,
          pCapDevice->GetDeviceObject(),
          pMdl,
          MappedSystemVa,
          pScatterList->dwBufferSize,
          FillScatterGatherList,
          &EContext,
          FALSE );

        if( nStat == STATUS_SUCCESS )
          break;

        KeStallExecutionProcessor(50);
      }

      KeLowerIrql(oldirql);

      if( nStat != STATUS_SUCCESS )
      {
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);

		DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "    LOCK_DMA::  GetSGList failed with = %x map regs = %d\r\n",
                 nStat, pCapDevice->m_NumberOfMapRegisters);
      }

      // Stall until GetScatterGatherList completes
      if( nStat == STATUS_SUCCESS )
      {
        while( (pScatterList->dwNumberListEntries == 0 ) && iTimeout++ < 100000 )
          KeStallExecutionProcessor(20);
      }
      
      // if the lock is ok, then copy the sg list to the libary
      if( pScatterList->dwNumberListEntries )
      {
        // Store MDL's locally in the driver, pass back an index into the list
        // find the first open slot in the list.  I'm guessing that this should never
        // fill more than 2 or 3 entries since most operations Lock/DMA/Unlock before 
        // doing another buffer, except for streaming which will lock a whole bunch
        for( i = 0; i < 1024; i++ )
        {
          if (pCapDevice->m_pGrabber->m_DMAInfo[i].pMDL == 0 )
          {
            pCapDevice->m_pGrabber->m_DMAInfo[i].pMDL = pMdl;
            pCapDevice->m_pGrabber->m_DMAInfo[i].pSysScatterGatherList = EContext.pSysScatterGatherList;
            pScatterList->dwMemHandle = i;
            pCapDevice->m_pGrabber->m_LockedBufferCount++;
            break;
          }
        }

        Irp->IoStatus.Information  = sizeof(I_SCATTER_LIST) +
          ( pScatterList->dwNumberListEntries * sizeof( MEMORY_BLOCK ) );
        
        memcpy( Irp->AssociatedIrp.SystemBuffer, pScatterList, Irp->IoStatus.Information );
      }
      else
      {
        // error condition, set variables so the library will know to fail, 
        // and return the scatter list without any blocks
        Irp->IoStatus.Information = sizeof(I_SCATTER_LIST);
        pScatterList->dwMemHandle = MAXDWORD32;
        memcpy( Irp->AssociatedIrp.SystemBuffer, pScatterList, sizeof(I_SCATTER_LIST) );
      }

      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }

    case IOCTL_HIDEF_UNLOCK_DMA_BUFFER:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_UNLOCK_DMA_BUFFER.");

      InLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
      OutLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

      I_SCATTER_LIST *pScatterList = (I_SCATTER_LIST *)Irp->AssociatedIrp.SystemBuffer;
      
      if(pScatterList->dwMemHandle != -1)
      {
        PSCATTER_GATHER_LIST pSysScatterGatherList = pCapDevice->m_pGrabber->m_DMAInfo[pScatterList->dwMemHandle].pSysScatterGatherList;

        if(pSysScatterGatherList != 0)
        {
          KIRQL oldirql;
          ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
          KeRaiseIrql(DISPATCH_LEVEL, &oldirql);

          // Delete the system-generated scatter gather list
          pCapDevice->m_DmaAdapterObject->DmaOperations->PutScatterGatherList(
            pCapDevice->m_DmaAdapterObject,
            pCapDevice->m_pGrabber->m_DMAInfo[pScatterList->dwMemHandle].pSysScatterGatherList,
            FALSE
          );

          KeLowerIrql(oldirql);

          pCapDevice->m_pGrabber->m_DMAInfo[pScatterList->dwMemHandle].pSysScatterGatherList = 0;
        }
        
        PMDL mdlLockedPages = pCapDevice->m_pGrabber->m_DMAInfo[pScatterList->dwMemHandle].pMDL;

        if(mdlLockedPages != 0)
        {
          // remove entry from list
          MmUnlockPages(mdlLockedPages);
          IoFreeMdl(mdlLockedPages);
          pCapDevice->m_pGrabber->m_LockedBufferCount--;
          pCapDevice->m_pGrabber->m_DMAInfo[pScatterList->dwMemHandle].pMDL = 0;
        }
        
        pScatterList->dwMemHandle = MAXDWORD32;
      }
            
      *(ULONG *)Irp->AssociatedIrp.SystemBuffer = TRUE;
      Irp->IoStatus.Information  = sizeof(ULONG);

      //Irp->IoStatus.Status = STATUS_SUCCESS;
      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }

    // read the pci configuration space and pass back
    case IOCTL_HIDEF_GET_PCI_CONFIG:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_GET_PCI_CONFIG.");

      ULONG bytesRead;
      UCHAR *pBuffer;

      Irp->IoStatus.Information = 0;  // Assume failure
      pBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
      

      bytesRead = pCapDevice->m_BusInterface.GetBusData(
                    pCapDevice->m_BusInterface.Context,
                     PCI_WHICHSPACE_CONFIG, //READ
                     pBuffer,
                     FIELD_OFFSET(PCI_COMMON_CONFIG, VendorID),
                     64);

      Irp->IoStatus.Information = bytesRead;
      
      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }
    break;

    case IOCTL_HIDEF_SET_PCI_CONFIG:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_SET_PCI_CONFIG.");

      ULONG bytesRead;
      UCHAR *pBuffer;
      USHORT Command = 0;
          
      Irp->IoStatus.Information = 0;  // Assume failure
      pBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
      

      bytesRead = pCapDevice->m_BusInterface.SetBusData(
                    pCapDevice->m_BusInterface.Context,
                     PCI_WHICHSPACE_CONFIG, //READ
                     pBuffer,
                     FIELD_OFFSET(PCI_COMMON_CONFIG, VendorID),
                     64);

      Irp->IoStatus.Information = bytesRead;

      pCapDevice->m_BusInterface.GetBusData(
        pCapDevice->m_BusInterface.Context,
        PCI_WHICHSPACE_CONFIG, //READ
        &Command,
        FIELD_OFFSET(PCI_COMMON_CONFIG, Command),
        sizeof(USHORT));

      // and enable memory on the bus
      Command |= 0x03;

      pCapDevice->m_BusInterface.SetBusData(
        pCapDevice->m_BusInterface.Context,
        PCI_WHICHSPACE_CONFIG, //READ
        &Command,
        FIELD_OFFSET(PCI_COMMON_CONFIG, Command),
        sizeof(USHORT));

      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }

    case IOCTL_HIDEF_ENABLE_TRIGGER_EVENT:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_ENABLE_TRIGGER_EVENT.");

      NTSTATUS obStatus;
      TRIGGER_EVENT_INFO *pTriggerEventInfo = (TRIGGER_EVENT_INFO *)Irp->AssociatedIrp.SystemBuffer;
      ULONG dwIRQEnables;
      PKEVENT pkAppEvent;

      if( pTriggerEventInfo == 0 )
      {
				DECORATED_DEBUG("", "Null handle passed to EnableTriggerEvent\r\n");
        break;
      }
      if( pCapDevice == 0 )
      {
				DECORATED_DEBUG("", "pCapDevice is null in EnableTriggerEvent\r\n");
        break;
      }

//      HANDLE  hUserEvent = (HANDLE)((ULONG_PTR)pTriggerEventInfo->hEvent);
      HANDLE  hUserEvent = (HANDLE)(pTriggerEventInfo->hEvent);

      // Dont nest enables.
      if( pCapDevice->m_pGrabber->m_TriggerEvent.bEnabled )
      {
				DECORATED_DEBUG("", "Grabber Trigger is ALREADY enabled\r\n");
        *(ULONG *)Irp->AssociatedIrp.SystemBuffer = TRUE;
        Irp->IoStatus.Information = sizeof(BOOLEAN);
        break;
      }

      if( hUserEvent == 0 )
      {
				DECORATED_DEBUG("", "Null Event Passed to EnableTriggerEvent\r\n");
        pkAppEvent = 0;
        //break;
      }
      else
      {
		// kjm - Jack, in retrospect, this doesn't seem to cause a problem even when called in Kernel Mode, but it appears to be a UserMode event so I changed it
		// kjm - TEST - if this is a User Created Event, the access mode should be UserMode, not KernelMode
	// OLD
		// obStatus = ObReferenceObjectByHandle( hUserEvent, 0, NULL,
        //                                      KernelMode, (PVOID *)&pkAppEvent, NULL);
	// NEW
		obStatus = ObReferenceObjectByHandle(hUserEvent, 0, NULL,
			UserMode, (PVOID *)&pkAppEvent, NULL);

        if( obStatus != STATUS_SUCCESS )
        {
					DECORATED_DEBUG("", "ObReferenceOBjectHandle failed, code = %x\r\n",(ULONG)obStatus);
          pkAppEvent = (PKEVENT)hUserEvent;
        }
      }
      
      pCapDevice->m_pGrabber->m_TriggerEvent.bh       = pTriggerEventInfo->bh;
      pCapDevice->m_pGrabber->m_TriggerEvent.hEvent   = pkAppEvent;
      pCapDevice->m_pGrabber->m_TriggerEvent.bOneShot = pTriggerEventInfo->bOneShot;
      pCapDevice->m_pGrabber->m_TriggerEvent.bEnabled = TRUE;

      Irp->IoStatus.Information = 0;
      
      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    } 

    case IOCTL_HIDEF_DISABLE_TRIGGER_EVENT:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_DISABLE_TRIGGER_EVENT.");

      TRIGGER_EVENT_INFO *pTriggerEventInfo = (TRIGGER_EVENT_INFO *)Irp->AssociatedIrp.SystemBuffer;

      if( pTriggerEventInfo == 0 )
      {
				DECORATED_DEBUG("", "Null handle passed to disableTriggerEvent\r\n");
        break;
      }
      if( pCapDevice == 0 )
      {
				DECORATED_DEBUG("", "pCapDevice is null in  disableTriggerEvent\r\n");
        break;
      }

      pCapDevice->m_pGrabber->m_TriggerEvent.bEnabled = FALSE;
      // Clear up the event handle
      if( pCapDevice->m_pGrabber->m_TriggerEvent.hEvent != 0 )
      {
        ObDereferenceObject(pCapDevice->m_pGrabber->m_TriggerEvent.hEvent);
        pCapDevice->m_pGrabber->m_TriggerEvent.hEvent = 0;
      }

      Irp->IoStatus.Information = 0;

      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }
  
    case IOCTL_HIDEF_ENABLE_DRIVER_EVENT:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,"IOCTL_HIDEF_ENABLE_DRIVER_EVENT.");

      NTSTATUS obStatus;
      DRIVER_EVENT *pDriverEvent = (DRIVER_EVENT *)Irp->AssociatedIrp.SystemBuffer;

      if( pDriverEvent == 0 )
      {
				DECORATED_DEBUG("", "Null pointer passed to EnableDriverEvent\r\n");
        goto IOCTL_HIDEF_ENABLE_DRIVER_EVENT_Exit;
      }

      if( pCapDevice == 0 )
      {
				DECORATED_DEBUG("", "pCapDevice is null in  EnableDriverEvent\r\n");
        goto IOCTL_HIDEF_ENABLE_DRIVER_EVENT_Exit;
      }

      HANDLE  hUserEvent = (HANDLE)pDriverEvent->qwEventHandle;
      PKEVENT pkDriverEvent;

      if( hUserEvent == 0 )
      {
				DECORATED_DEBUG("", "Null Event Passed to EnableDriverEvent\r\n");
        goto IOCTL_HIDEF_ENABLE_DRIVER_EVENT_Exit;
      }

      if(pDriverEvent->dwEventIndex < NUM_DRIVER_EVENTS)
      {
				DECORATED_DEBUG("", "Enable event %d.\r\n", pDriverEvent->dwEventIndex);
#if 0
        // This must be called at PASSIVE LEVEL.
        obStatus = ObReferenceObjectByHandle(
	            hUserEvent,
              0,
              NULL,
              KernelMode,
              (PVOID *)&pkDriverEvent, 
              NULL);
#else
        // This must be called at PASSIVE LEVEL.
        obStatus = ObReferenceObjectByHandle(
	            hUserEvent,
              EVENT_MODIFY_STATE,
              *ExEventObjectType,
              UserMode,
              (PVOID *)&pkDriverEvent, 
              NULL);
#endif

        if( obStatus != STATUS_SUCCESS )
        {
					DECORATED_DEBUG("", "ObReferenceOBjectHandle failed, code = %x\r\n",(ULONG)obStatus);
          pkDriverEvent = (PKEVENT)0;
        }

        pCapDevice->m_hDriverEvents[pDriverEvent->dwEventIndex]             = pkDriverEvent;
        pCapDevice->m_pGrabber->m_pDriverEvents[pDriverEvent->dwEventIndex] = pkDriverEvent;
      }
            

IOCTL_HIDEF_ENABLE_DRIVER_EVENT_Exit:
      Irp->IoStatus.Information = 0;
      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    } 

    case IOCTL_HIDEF_DISABLE_DRIVER_EVENT:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                      "CCaptureDevice::DispatchControl() - IOCTL_HIDEF_DISABLE_DRIVER_EVENT.");

      if( pCapDevice == 0 )
      {
				DECORATED_DEBUG("", "pCapDevice is null in  DisableDriverEvent\r\n");
        goto IOCTL_HIDEF_DISABLE_DRIVER_EVENT_Exit;
      }

      DRIVER_EVENT *pDriverEvent = (DRIVER_EVENT *)Irp->AssociatedIrp.SystemBuffer;

      if( pDriverEvent == 0 )
      {
				DECORATED_DEBUG("", "Null pointer passed to DisableDriverEvent\r\n");
        goto IOCTL_HIDEF_DISABLE_DRIVER_EVENT_Exit;
      }

      if(pDriverEvent->dwEventIndex < NUM_DRIVER_EVENTS)
      {
        // Clear up the event handle
        if( pCapDevice->m_hDriverEvents[pDriverEvent->dwEventIndex] != 0 )
        {
					DECORATED_DEBUG("", "Disable event %d.\r\n", pDriverEvent->dwEventIndex);
          ObDereferenceObject(pCapDevice->m_hDriverEvents[pDriverEvent->dwEventIndex]);
          pCapDevice->m_hDriverEvents[pDriverEvent->dwEventIndex] = 0;
          pCapDevice->m_pGrabber->m_pDriverEvents[pDriverEvent->dwEventIndex] = 0;
        }
      }
      
IOCTL_HIDEF_DISABLE_DRIVER_EVENT_Exit:
      Irp->IoStatus.Information = 0;
      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }

    case IOCTL_HIDEF_ALLOCATE_MAILBOX:
    {
      PVOID pvUserAddress = 0;

      if( pCapDevice->pMailBox )
      {      
        // allocate memory area shared between driver and proxy DLL
        pCapDevice->pmdlMailBox = pCapDevice->MyIoAllocateMdl( (PVOID)pCapDevice->pMailBox,
                   MAILBOX_SIZE, FALSE, FALSE, NULL );

        if( !pCapDevice->pmdlMailBox )
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "IOCTL_HIDEF_ALLOCATE_MAILBOX - Returning STATUS_INSUFFICIENT_RESOURCES\r\n"
                          "    Can't allocate MDL - pCapDevice->pmdlMailBox == 0");

          status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
           _try
          {
            MmBuildMdlForNonPagedPool(pCapDevice->pmdlMailBox);
          }
           _except(EXCEPTION_EXECUTE_HANDLER)
          {
            if( pCapDevice->pmdlMailBox )
              IoFreeMdl( pCapDevice->pmdlMailBox );

            pCapDevice->pmdlMailBox = 0;
          }

          if( pCapDevice->pmdlMailBox )
          {
            memset( pCapDevice->pMailBox, 0, MAILBOX_SIZE );
            pvUserAddress = 0;

            _try
            {
              pvUserAddress = MmMapLockedPagesSpecifyCache( pCapDevice->pmdlMailBox, 
                   UserMode, MmNonCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute );
            }
            _except(EXCEPTION_EXECUTE_HANDLER)
            {
              pvUserAddress = 0;
              NTSTATUS code = GetExceptionCode(); 
              DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                              "IOCTL_HIDEF_ALLOCATE_MAILBOX. \r\n"
                              "    Call to MmMapLockedPagesSpecifyCache() failed due to exception 0x%0x", code);
            }
          }

          if( pvUserAddress == 0 )
          {
            DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                            "IOCTL_HIDEF_ALLOCATE_MAILBOX. \r\n"
                            "    Can't lock MDL into user space - pvUserAddress == 0");
            if( pCapDevice->pmdlMailBox )
              IoFreeMdl( pCapDevice->pmdlMailBox );

            pCapDevice->pmdlMailBox = 0;
            break;
          }
          else
          {
            DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                            "IOCTL_HIDEF_ALLOCATE_MAILBOX - Returning STATUS_SUCCESS.");
            pCapDevice->pUserMappedMailBox = reinterpret_cast<PMAILBOX>(pvUserAddress);
            *((PVOID *)(Irp->AssociatedIrp.SystemBuffer)) = pCapDevice->pUserMappedMailBox;
            status = STATUS_SUCCESS;
          } 
        }
      }
      else
      {
        DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                        "IOCTL_HIDEF_ALLOCATE_MAILBOX - Returning STATUS_INSUFFICIENT_RESOURCES\r\n"
                        "    Driver init failure! - pCapDevice->pMailBox == 0");
        status = STATUS_INSUFFICIENT_RESOURCES;
      }
      
      Irp->IoStatus.Information  = sizeof(PVOID);

      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return status;
    }

    case IOCTL_HIDEF_DEALLOCATE_MAILBOX:
    {
      if( pCapDevice->pMailBox == 0 )
      {
        DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                        "IOCTL_HIDEF_DEALLOCATE_MAILBOX. \r\n"
                        "    Driver init failure! - pCapDevice->pMailBox == 0");
      }
      else if( pCapDevice->pUserMappedMailBox == 0 )
      {
        DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                        "IOCTL_HIDEF_DEALLOCATE_MAILBOX. \r\n"
                        "    Already deallocated - pCapDevice->pUserMappedMailBox == 0");
      }
      else
      {
        DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                        "IOCTL_HIDEF_DEALLOCATE_MAILBOX.");

        if( pCapDevice->pmdlMailBox )
        {
          if( pCapDevice->pUserMappedMailBox )
            MmUnmapLockedPages( pCapDevice->pUserMappedMailBox, pCapDevice->pmdlMailBox );

          if( pCapDevice->pmdlMailBox )
            IoFreeMdl( pCapDevice->pmdlMailBox );
            
          pCapDevice->pUserMappedMailBox = 0;
          pCapDevice->pmdlMailBox = 0;
        }
      }
      
      Irp->IoStatus.Information = 0;

      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }

  // load the board's RSET registers from an array created by the plugin
  // tbd - return the board's register set for the GET command
    case IOCTL_HIDEF_SET_RSET:
    {
      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_SET_RSET");

      RSET *pRSet = (RSET *)Irp->AssociatedIrp.SystemBuffer;
      ULONG ulSize = IoGetCurrentIrpStackLocation( Irp )->Parameters.DeviceIoControl.InputBufferLength;
      
      pCapDevice->m_pGrabber->SetSignalAttributes(pRSet);

      Irp->IoStatus.Information = 0;

      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }

    case IOCTL_HIDEF_SET_PIN_FORMAT:
    {
      PIN_FORMAT *pPinFormat = static_cast<PIN_FORMAT *>(Irp->AssociatedIrp.SystemBuffer);
      ULONG ulSize = IoGetCurrentIrpStackLocation( Irp )->Parameters.DeviceIoControl.InputBufferLength;
      PKS_DATARANGE_VIDEO_PALETTE pFormat;

      long lWidth = pPinFormat->dwWidth;
      long lHeight = pPinFormat->dwHeight;
      LONGLONG llFrameTime100ns = pPinFormat->llFrameTime100ns;
	  GUID SubFormatGuid = { 0 };

      if(pPinFormat->dwDataType == KS_BI_RGB)
      {
        switch(pPinFormat->dwBitsPerPixel)
        {
          case 8:
          { 
            GUID g = { MY_MEDIASUBTYPE_RGB8 };
            SubFormatGuid = g;
          }  break;
          
          case 16:
          {
            GUID g = { MY_MEDIASUBTYPE_RGB555 };
            SubFormatGuid = g;
          }  break;

          case 24:
          { 
            GUID g = { MY_MEDIASUBTYPE_RGB24 };
            SubFormatGuid = g;
          }  break;

          case 32:
          {
            GUID g = { MY_MEDIASUBTYPE_RGB32 };
            SubFormatGuid = g;
          }  break;
        }
      }
      else if(pPinFormat->dwDataType == FOURCC_YUY2)
      {
        GUID g = { MY_MEDIASUBTYPE_YUY2 };
        SubFormatGuid = g;
      }

      switch(pPinFormat->dwPinType)
      {
        default:
        case PINTYPE_CAPTURE:
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "IOCTL_HIDEF_SET_PIN_FORMAT - PINTYPE_CAPTURE\r\n"
                          "    Set - Width = %d, Height = %d, Bpp = %d, FrameTime100ns = %I64d",
                          lWidth, lHeight, pPinFormat->dwBitsPerPixel, llFrameTime100ns);

          pFormat = &Format_InputCapture;
          pFormat->VideoInfo.bmiHeader.biCompression = pPinFormat->dwDataType;
          pFormat->VideoInfo.bmiHeader.biBitCount    = (WORD)pPinFormat->dwBitsPerPixel;
          AdjustVideoFormat(pFormat, lWidth, lHeight, lWidth, lHeight, llFrameTime100ns);
          //AdjustFixedFormats(lWidth, lHeight, lWidth, lHeight, llFrameTime100ns);
          pFormat->DataRange.SubFormat = SubFormatGuid;
          pCapDevice->m_pGrabber->AllocateCaptureMessageBitmap(&pFormat->VideoInfo);
          break;
        }

        case PINTYPE_PREVIEW:
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "IOCTL_HIDEF_SET_PIN_FORMAT - PINTYPE_PREVIEW\r\n"
                          "    Set - Width = %d, Height = %d, Bpp = %d, FrameTime100ns = %I64d",
                          lWidth, lHeight, pPinFormat->dwBitsPerPixel, llFrameTime100ns);

          pFormat = &Format_PreferredPreview;
          pFormat->VideoInfo.bmiHeader.biCompression = pPinFormat->dwDataType;
          pFormat->VideoInfo.bmiHeader.biBitCount    = (WORD)pPinFormat->dwBitsPerPixel;
          AdjustVideoFormat(pFormat, lWidth, lHeight, lWidth, lHeight, llFrameTime100ns);
          pFormat->DataRange.SubFormat = SubFormatGuid;
          pCapDevice->m_pGrabber->AllocatePreviewMessageBitmap(&pFormat->VideoInfo);
          break;
        }

        case PINTYPE_COMPRESS:
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "IOCTL_HIDEF_SET_PIN_FORMAT - PINTYPE_COMPRESS\r\n"
                          "    Set - Width = %d, Height = %d, Bpp = %d, FrameTime100ns = %I64d",
                          lWidth, lHeight, pPinFormat->dwBitsPerPixel, llFrameTime100ns);

          KS_DATARANGE_MPEG2_VIDEO *pCompressFormat = &Format_Compress;
          pCompressFormat->VideoInfoHeader.hdr.bmiHeader.biCompression = pPinFormat->dwDataType;
          pCompressFormat->VideoInfoHeader.hdr.bmiHeader.biBitCount    = (WORD)pPinFormat->dwBitsPerPixel;
          AdjustCompressFormat(pCompressFormat, lWidth, lHeight, lWidth, lHeight, llFrameTime100ns, -1, -1, -1, -1, -1);
          break;
        }
      }

      Irp->IoStatus.Information = 0;

      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }
    
    case IOCTL_HIDEF_GET_PIN_FORMAT:
    {
      PIN_FORMAT *pPinFormat = static_cast<PIN_FORMAT *>(Irp->AssociatedIrp.SystemBuffer);
      ULONG ulSize = IoGetCurrentIrpStackLocation( Irp )->Parameters.DeviceIoControl.InputBufferLength;
      PKS_DATARANGE_VIDEO_PALETTE pFormat;

      switch(pPinFormat->dwPinType)
      {
        default:
        case PINTYPE_CAPTURE:
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_GET_PIN_FORMAT - PINTYPE_CAPTURE");

          pFormat = &Format_InputCapture;
          pPinFormat->dwDataType       = pFormat->VideoInfo.bmiHeader.biCompression;
          pPinFormat->dwWidth          = pFormat->VideoInfo.bmiHeader.biWidth;
          pPinFormat->dwHeight         = pFormat->VideoInfo.bmiHeader.biHeight;
          pPinFormat->dwBitsPerPixel   = pFormat->VideoInfo.bmiHeader.biBitCount;
          pPinFormat->llFrameTime100ns = pFormat->VideoInfo.AvgTimePerFrame; 
          pPinFormat->uuidSubType      = pFormat->DataRange.SubFormat;

          break;
        }

        case PINTYPE_PREVIEW:
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_GET_PIN_FORMAT - PINTYPE_PREVIEW");

          pFormat = &Format_PreferredPreview;
          pPinFormat->dwDataType       = pFormat->VideoInfo.bmiHeader.biCompression;
          pPinFormat->dwWidth          = pFormat->VideoInfo.bmiHeader.biWidth;
          pPinFormat->dwHeight         = pFormat->VideoInfo.bmiHeader.biHeight;
          pPinFormat->dwBitsPerPixel   = pFormat->VideoInfo.bmiHeader.biBitCount;
          pPinFormat->llFrameTime100ns = pFormat->VideoInfo.AvgTimePerFrame; 
          pPinFormat->uuidSubType      = pFormat->DataRange.SubFormat;

          break;
        }

        case PINTYPE_COMPRESS:
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo, "IOCTL_HIDEF_GET_PIN_FORMAT - PINTYPE_COMPRESS");

          KS_DATARANGE_MPEG2_VIDEO *pCompressFormat = &Format_Compress;
          pPinFormat->dwDataType       = pCompressFormat->VideoInfoHeader.hdr.bmiHeader.biCompression;
          pPinFormat->dwWidth          = pCompressFormat->VideoInfoHeader.hdr.bmiHeader.biWidth;
          pPinFormat->dwHeight         = pCompressFormat->VideoInfoHeader.hdr.bmiHeader.biHeight;
          pPinFormat->dwBitsPerPixel   = pCompressFormat->VideoInfoHeader.hdr.bmiHeader.biBitCount;
          pPinFormat->llFrameTime100ns = pCompressFormat->VideoInfoHeader.hdr.AvgTimePerFrame; 
          pPinFormat->uuidSubType      = pCompressFormat->DataRange.SubFormat;

          break;
        }
      }
      
      Irp->IoStatus.Information = sizeof(PIN_FORMAT);

      IoCompleteRequest (Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
    }
    
    case IOCTL_KS_PROPERTY:
    {
		//      KSPROPSETID_Pin

		// kjm - TEST - this code causes Verifier errors, let this case fall through to the bottom and generically handle at the end of the method
		/* status = m_OrigDispatchControl(DeviceObject, Irp);

		KSPROPERTY *pKsProperty = (KSPROPERTY *)Irp->AssociatedIrp.SystemBuffer;

		if (Irp->MdlAddress)
			pKsProperty = (KSPROPERTY *)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		*/

      
#if 0
      if(pCapDevice)
      {
        if(pKsProperty)
        {
          if(pCapDevice->m_pGrabber)
          {
            DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                            "IOCTL_KS_PROPERTY returned %x.\r\n"
                            "    GUID = 0x%lx, 0x%x, 0x%x, {0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x}\r\n"
                            "    ID = %x, Flags = %x", status,
		                        pKsProperty->Set.Data1, pKsProperty->Set.Data2, pKsProperty->Set.Data3,
		                        pKsProperty->Set.Data4[0], pKsProperty->Set.Data4[1], pKsProperty->Set.Data4[2],
		                        pKsProperty->Set.Data4[3], pKsProperty->Set.Data4[4], pKsProperty->Set.Data4[5],
		                        pKsProperty->Set.Data4[6], pKsProperty->Set.Data4[7],
                            pKsProperty->Id, pKsProperty->Flags);
          }
          else
          {
            DECORATED_DEBUG("",
                            "IOCTL_KS_PROPERTY returned %x.\r\n"
                            "    GUID = 0x%lx, 0x%x, 0x%x, {0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x}\r\n"
                            "    ID = %x, Flags = %x", status,
		                        pKsProperty->Set.Data1, pKsProperty->Set.Data2, pKsProperty->Set.Data3,
		                        pKsProperty->Set.Data4[0], pKsProperty->Set.Data4[1], pKsProperty->Set.Data4[2],
		                        pKsProperty->Set.Data4[3], pKsProperty->Set.Data4[4], pKsProperty->Set.Data4[5],
		                        pKsProperty->Set.Data4[6], pKsProperty->Set.Data4[7],
                            pKsProperty->Id, pKsProperty->Flags);
          }
        }
        else
        {
          if(pCapDevice->m_pGrabber)
          {
            DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                            "IOCTL_KS_PROPERTY returned %x.\r\n"
                            "    AssociatedIrp.SystemBuffer (pKsProperty) = 0", status);
          }
          else
          {
            DECORATED_DEBUG("",
                            "IOCTL_KS_PROPERTY returned %x.\r\n"
                            "    AssociatedIrp.SystemBuffer (pKsProperty) = 0", status);
          }
        }
      }
      else
      {
        DECORATED_DEBUG("",
                        "IOCTL_KS_PROPERTY returned %x.\r\n"
                        "    pCapDevice = 0", status);
      }
#endif
	  // kjm - TEST
      //return status;
    }
/*
    case IOCTL_KS_ENABLE_EVENT:
    {
      
      status =  m_OrigDispatchControl( DeviceObject, Irp );

      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                      "CCaptureDevice::DispatchControl() - IOCTL_KS_ENABLE_EVENT returned %x", status);
      return status;
    }

    case IOCTL_KS_DISABLE_EVENT:
    {
      status =  m_OrigDispatchControl( DeviceObject, Irp );

      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                      "CCaptureDevice::DispatchControl() - IOCTL_KS_DISABLE_EVENT returned %x", status);
      return status;
    }

    case IOCTL_KS_METHOD:
    {
      status =  m_OrigDispatchControl( DeviceObject, Irp );

//      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
//                      "CCaptureDevice::DispatchControl() - IOCTL_KS_METHOD returned %x", status);

      KSPROPERTY *pKsProperty = (KSPROPERTY *)Irp->AssociatedIrp.SystemBuffer;

      if(Irp->MdlAddress)
        pKsProperty = (KSPROPERTY *)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
      
      if(pCapDevice)
      {
        if(pKsProperty)
        {
          if(pCapDevice->m_pGrabber)
          {
            DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                            "CCaptureDevice::DispatchControl() - IOCTL_KS_METHOD returned %x.\r\n"
                            "    GUID = 0x%lx, 0x%x, 0x%x, {0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x}\r\n"
                            "    ID = %x, Flags = %x", status,
                            pKsProperty->Set.Data1, pKsProperty->Set.Data2, pKsProperty->Set.Data3,
                            pKsProperty->Set.Data4[0], pKsProperty->Set.Data4[1], pKsProperty->Set.Data4[2],
                            pKsProperty->Set.Data4[3], pKsProperty->Set.Data4[4], pKsProperty->Set.Data4[5],
                            pKsProperty->Set.Data4[6], pKsProperty->Set.Data4[7],
                            pKsProperty->Id, pKsProperty->Flags);
          }
          else
          {
            DECORATED_DEBUG("",
                            "CCaptureDevice::DispatchControl() - IOCTL_KS_METHOD returned %x.\r\n"
                            "    GUID = 0x%lx, 0x%x, 0x%x, {0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x}\r\n"
                            "    ID = %x, Flags = %x", status,
                            pKsProperty->Set.Data1, pKsProperty->Set.Data2, pKsProperty->Set.Data3,
                            pKsProperty->Set.Data4[0], pKsProperty->Set.Data4[1], pKsProperty->Set.Data4[2],
                            pKsProperty->Set.Data4[3], pKsProperty->Set.Data4[4], pKsProperty->Set.Data4[5],
                            pKsProperty->Set.Data4[6], pKsProperty->Set.Data4[7],
                            pKsProperty->Id, pKsProperty->Flags);
          }
        }
        else
        {
          if(pCapDevice->m_pGrabber)
          {
            DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                            "CCaptureDevice::DispatchControl() - IOCTL_KS_METHOD returned %x.\r\n"
                            "    AssociatedIrp.SystemBuffer (pKsProperty) = 0", status);
          }
          else
          {
            DECORATED_DEBUG("",
                            "CCaptureDevice::DispatchControl() - IOCTL_KS_METHOD returned %x.\r\n"
                            "    AssociatedIrp.SystemBuffer (pKsProperty) = 0", status);
          }
        }
      }
      else
      {
        DECORATED_DEBUG("",
                        "CCaptureDevice::DispatchControl() - IOCTL_KS_METHOD returned %x.\r\n"
                        "    pCapDevice = 0", status);
      }
      
      return status;
    }

    case IOCTL_KS_WRITE_STREAM:
    {
      status =  m_OrigDispatchControl( DeviceObject, Irp );

      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                      "CCaptureDevice::DispatchControl() - IOCTL_KS_WRITE_STREAM returned %x", status);
      return status;
    }

    case IOCTL_KS_READ_STREAM:
    {
      status =  m_OrigDispatchControl( DeviceObject, Irp );

//      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
//                      "CCaptureDevice::DispatchControl() - IOCTL_KS_READ_STREAM returned %x", status);
      return status;
    }

    case IOCTL_KS_RESET_STATE:
    {
      status =  m_OrigDispatchControl( DeviceObject, Irp );

      DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                      "CCaptureDevice::DispatchControl() - IOCTL_KS_RESET_STATE returned %x", status);
      return status;
    }
*/

    case IOCTL_KS_READ_STREAM:
      break;

    default:
    {
      if(pCapDevice)
      {
        if(pCapDevice->m_pGrabber)
        {
          DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
                          "Unknown IOCTL code %x.",
                          IoControlCode);
        }
        else
        {
          DECORATED_DEBUG("", "Unknown IOCTL code %x.    m_pGrabber = 0.", IoControlCode);
        }
      }
      else
      {
        DECORATED_DEBUG("", "Unknown IOCTL code %x.    pCapDevice = 0.", IoControlCode);
      }
      
      break;
    }
  }

  // and pass the IOCTL on to the device object chain
  if(m_OrigDispatchControl)
  {
    status = m_OrigDispatchControl( DeviceObject, Irp );
  
    //// Block IOCTL_KS_READ_STREAM, too many calls. 
    //if(IoControlCode != IOCTL_KS_READ_STREAM)
    //{
    //  DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
    //                "CCaptureDevice::DispatchControl(%x) - m_OrigDispatchControl(%016p, %016p) returned %x", IoControlCode, DeviceObject, Irp, status);
    //}
  }
  else
  {
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    status = STATUS_SUCCESS;
  }
  
  return status;
}

// This is defined in <wdmguid.h> - but to pull that in requires <wdm.h> and
// that causes all kinds of linkage problems.
//DEFINE_GUID(GUID_BUS_INTERFACE_STANDARD, 0x496B8280L, 0x6F25, 0x11D0, 0xBE, 0xAF, 0x08, 0x00, 0x2B, 0xE2, 0x09, 0x2F);


NTSTATUS
CCaptureDevice::FsiGetStandardInterface(
    IN PDEVICE_OBJECT DeviceObject,
    OUT PBUS_INTERFACE_STANDARD BusInterface
    )
/*++
Routine Description:

    This routine gets the bus interface standard information from the PDO.
    
Arguments:
    DeviceObject - Device object to query for this information.
    BusInterface - Supplies a pointer to the retrieved information.
    
Return Value:

    NT status.
    
--*/ 
{
  KEVENT event;
  NTSTATUS status;
  PIRP irp;
  IO_STATUS_BLOCK ioStatusBlock;
  PIO_STACK_LOCATION irpStack;
  PDEVICE_OBJECT targetObject;

  
  if( DeviceObject == 0 )
    return STATUS_INVALID_PARAMETER;

  KeInitializeEvent( &event, NotificationEvent, FALSE );
  
  targetObject = IoGetAttachedDeviceReference( DeviceObject );
  
  irp = IoBuildSynchronousFsdRequest( IRP_MJ_PNP,
                                      targetObject,
                                      NULL,
                                      0,
                                      NULL,
                                      &event,
                                      &ioStatusBlock );

  const GUID GuidBusInterfaceStandard = GUID_BUS_INTERFACE_STANDARD;

  if( irp != NULL )
  {
    irpStack = IoGetNextIrpStackLocation( irp );
    irpStack->MinorFunction = IRP_MN_QUERY_INTERFACE;
    irpStack->Parameters.QueryInterface.InterfaceType = 
                        (LPGUID) &GuidBusInterfaceStandard;
    irpStack->Parameters.QueryInterface.Size = sizeof(BUS_INTERFACE_STANDARD);
    irpStack->Parameters.QueryInterface.Version = 1;
    irpStack->Parameters.QueryInterface.Interface = 
                                        (PINTERFACE)BusInterface;
    
    irpStack->Parameters.QueryInterface.InterfaceSpecificData = NULL;
    
    //    
    // Initialize the status to error in case the bus driver does not 
    // set it correctly.
    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    
    status = IoCallDriver( targetObject, irp );
    if (status == STATUS_PENDING) 
    {
		status = KeWaitForSingleObject( &event, Executive, KernelMode, FALSE, NULL);
		
      ASSERT(NT_SUCCESS(status));
      status = ioStatusBlock.Status;
    }
  }
  else
    status = STATUS_INSUFFICIENT_RESOURCES;

  // Done with reference
  ObDereferenceObject( targetObject );
  return status;
  
} 

NTSTATUS CCaptureDevice::Snap()
{
  return m_pGrabber->Snap();
}

void CCaptureDevice::GetBasePointers(BASEPTRINFO *pBasePtrs )
{
  m_pGrabber->GetBasePtrs( pBasePtrs, 6 );
}

// Fill in the report structure.
void CCaptureDevice::DoReport(
  HD_sReport  *phrptIn, 
  short       nIn, 
  HD_sReport  *phrptOut,
  short       nOut, 
  ULONG       *pdwRet
  ) 
{
  short      n, nHdrBytes, nEntryBytes, nEntries;
  HD_sReport hrpt;
  HD_sBoard  *pbr;
  USHORT     wCheck;
  int        m_Unit;

  /*
  // Compute the size of the report requested.
  */
  nHdrBytes   = sizeof(HD_sReport)-sizeof(hrpt.bra);
  nEntryBytes = sizeof(hrpt.bra)/HIDEF_MAX_BOARDS;
  if(nOut > sizeof(HD_sReport)) 
    nOut = sizeof(HD_sReport);
  n           = nOut-nHdrBytes;

  /*
  // Retrieve input parameters.
  */
  wCheck = 0;

  if( nIn == 0 ) // no input structure, just fill in the header for output
  {
    nEntries = 0;
    nOut     = nHdrBytes;
  }
  else
    nEntries = HIDEF_MAX_BOARDS;

  if((HD_sReport *) 0 == phrptOut ) 
  {
    nOut = 0;
    nEntries = 0;
  }
  
  /*
  // Prepare report.
  */
  // Copy the input report to the output report structure
  if(nEntries && phrptIn != 0) 
  {
    n = nHdrBytes + nEntries * nEntryBytes;
    memcpy(&hrpt,phrptIn,n);
  }

  // use the size of the pointer to determine if we are in 32 or 64 bit mode
  if( sizeof(void *) == 4 )
    hrpt.w32BitDriver = 1;
  else
    hrpt.w32BitDriver = 0;

  HANDLE hProcessID = PsGetCurrentProcessId();    

  // If the board is claimed make sure the claiming process is still running
  if(m_pGrabber->m_IsClaimed)
  {
    if(hProcessID != m_pGrabber->m_hClaimingProcessID)
    {
      PEPROCESS pEProcess = NULL;

      DECORATED_DEBUG(m_pGrabber->m_szSerialNo,
                      "Calling process is not claiming process %p.",
                       m_pGrabber->m_hClaimingProcessID);
      
      if(PsLookupProcessByProcessId( m_pGrabber->m_hClaimingProcessID, &pEProcess) == STATUS_INVALID_PARAMETER)
      {
        DECORATED_DEBUG(m_pGrabber->m_szSerialNo,
                        "Claiming process %4p not found, clearing claim.",
                         m_pGrabber->m_hClaimingProcessID);
        UnClaim();
      }
      else
      {
        LARGE_INTEGER timeout;
        timeout.QuadPart = 0x0;
        NTSTATUS status = 0;

        _try
        {
			status = KeWaitForSingleObject( pEProcess, Executive, KernelMode, FALSE, &timeout);

			ObDereferenceObject(pEProcess);
        }
        _except(EXCEPTION_EXECUTE_HANDLER)
        {
//          DECORATED_DEBUG(m_pGrabber->m_szSerialNo,
//                          "CCaptureDevice::DoReport() - Exception occurred in KeWaitForSingleObject(), peProcess = %x.",
//                           pEProcess);
          nOut = 0;
          nEntries = 0;
        }
        
	      if(status != STATUS_TIMEOUT)
        {
          DECORATED_DEBUG(m_pGrabber->m_szSerialNo,
                          "Claiming process %4p has exited, clearing claim.",
                          m_pGrabber->m_hClaimingProcessID);
          UnClaim();
        }
        else
        {
          DECORATED_DEBUG(m_pGrabber->m_szSerialNo,
                          "Claiming process %4p is still running.",
                          m_pGrabber->m_hClaimingProcessID);
        }
      }
    }
  }
    
  if(nOut >= 4)
  {
    hrpt.e = 0;
    hrpt.wRev = 0x490; 
    hrpt.nBrdCount++;

    if( nOut > nHdrBytes )
    {
  // nEntries should always only be 1....
      pbr           = &hrpt.bra[hrpt.nBrdList];
      pbr->nType    = m_pGrabber->m_FrameGrabberType;
      pbr->wID      = (unsigned short)m_pGrabber->m_DeviceNum; 
      pbr->wIO      = (unsigned short)m_pGrabber->m_DeviceNum + 1; //Library expects this to be non-zero
      pbr->cID      = (char)m_pGrabber->m_DeviceNum; //pBrd->m_cID;
      pbr->bClaim   = (short)m_pGrabber->m_IsClaimed;
      pbr->bh       = (BoardHandle)m_pGrabber->m_BoardHandle;
      memcpy(pbr->szSerial, m_pGrabber->m_szSerialNo, sizeof(pbr->szSerial));
      hrpt.nBrdList++;
    }
  }
  /*
  // Compute size of report then copy to output structure.
  */
  if(nEntries) 
  {
    nOut = nHdrBytes + nEntries*nEntryBytes;
  } 
  else 
  {
    if(nOut < 4) nOut = 0;
    else if(nOut < 6) nOut=4;
    else if(nOut < 8) nOut=6;
    else if(nOut < nHdrBytes) nOut = 8;
    else nOut = nHdrBytes;
  }

  //  fill in the output structure
  if(nOut && phrptOut != 0) 
  {
    memcpy(phrptOut,&hrpt,nOut);
  }

  *pdwRet = (ULONG)nOut;
}



void CCaptureDevice::Claim( 
  HDDRV_IO_CLAIM   *pClaimIn, 
  short            nIn, 
  HDDRV_IO_CLAIM   *pClaimOut,
  short            nOut,
  ULONG            *pdwRet)
{
  PMDL pmdlAMCC;
  PMDL pmdlBoardRegs;
  int i;

  DECORATED_DEBUG(m_pGrabber->m_szSerialNo, "Claiming board.");
  // set the claimed flag - so report will send back the correct value
  m_pGrabber->m_IsClaimed = 1;
  m_pGrabber->m_hClaimingProcessID = PsGetCurrentProcessId();

  // at claim time there better not be any locked buffers
  m_pGrabber->m_LockedBufferCount = 0;

  // initialize trigger event members
  m_pGrabber->m_TriggerEvent.bEnabled = FALSE;
  m_pGrabber->m_TriggerEvent.bh = 0;
  m_pGrabber->m_TriggerEvent.nResv = 0;
  m_pGrabber->m_TriggerEvent.bOneShot = FALSE;
  m_pGrabber->m_TriggerEvent.hEvent = 0;

  // intialize the list of locked-buffer mdls
  for( i = 0; i < 1024; i++)
  {
    m_pGrabber->m_DMAInfo[i].pMDL = NULL;
    m_pGrabber->m_DMAInfo[i].pSysScatterGatherList = 0;
  }

  m_pGrabber->m_BoardHandle = pClaimIn->bh;

  pClaimOut->e  = 0;

  m_pGrabber->UnmapBoardPointers();
  m_pGrabber->MapBoardPointers();

  *pdwRet = sizeof(HDDRV_IO_CLAIM);
}


void CCaptureDevice::UnClaim()
{
  int i;

  if(m_pGrabber->m_IsClaimed)
  {
    DECORATED_DEBUG(m_pGrabber->m_szSerialNo, "UnClaiming board.");

    // Clean any locked buffer pages - this will usually only happen if the
    // application crashes with locked pages, but exiting in this state
    // can cause the kernel to blue screen.  This will be replaced by a linked
    // list at some point....

    // Turn off any DMA
    m_pGrabber->m_pBoardRegisters->dwDMACTRL = 0;
    
    for( i = 0; i < 1024; i++)
    {
      PMDL mdlLockedPages = m_pGrabber->m_DMAInfo[i].pMDL;

      if (mdlLockedPages != 0)
      {
        // remove entry from list
        MmUnlockPages(mdlLockedPages);
        IoFreeMdl(mdlLockedPages);
        m_pGrabber->m_DMAInfo[i].pMDL = 0;
        m_pGrabber->m_DMAInfo[i].pSysScatterGatherList = 0;
      }
    }

    // clear the claimed flag - so report will send back the correct value
    m_pGrabber->m_IsClaimed = 0;
    m_pGrabber->m_hClaimingProcessID = 0;
    m_pGrabber->m_BoardHandle = 0;
    m_pGrabber->m_LockedBufferCount = 0;

//    m_pGrabber->UnmapBoardPointers();
  }
  else
  {
    DECORATED_DEBUG(m_pGrabber->m_szSerialNo, "Board wasn't claimed.");
  }
}

PMDL CCaptureDevice::MyIoAllocateMdl(PVOID pBuffer, ULONG dwBufferSize, BOOLEAN SecondaryBuffer,
  BOOLEAN ChargeQuota, PIRP Irp)
{
  int nTries = 20;   // 1ms
  int nRetries = 10; // 100ms
  PMDL pMdl = 0;
  
  for(int nRetry = 0; nRetry < nRetries - 1; nRetry++)
  {
    for(int nTry = 0; nTry < nTries; nTry++)
    {
      pMdl = IoAllocateMdl(pBuffer, dwBufferSize, FALSE, FALSE, NULL );
      
      if( pMdl != (PMDL) 0 ) 
        break;

      //DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
      DECORATED_DEBUG("",
        "Error on IoAllocateMdl(), addr 0x%px, size %d, Try %d\r\n",
        pBuffer, dwBufferSize, nTry);
        
      KeStallExecutionProcessor(50);
    }
    
    if( pMdl != (PMDL) 0 ) 
      break;

      //DECORATED_DEBUG(pCapDevice->m_pGrabber->m_szSerialNo,
      DECORATED_DEBUG("",
      "Error after %d IoAllocateMdl() tries, sleeping 10ms and trying again.\r\n", nTries);

    // Sleep 10ms and try again
    // Driver Verifier will sometimes fail many calls in a row.
    LARGE_INTEGER liDelay;
    liDelay.QuadPart = 10 * KE_TIME_1MS_RELATIVE;
    KeDelayExecutionThread( KernelMode, FALSE, &liDelay );
  }
  
  return pMdl;
}

// FillScatterGatherList is a callback from FillScatterGatherList.  As with
// ListControl() it is supposed to actually perform the IO, but in this case, I
// just fill in the entries of the upper level scatter/gather list.
// Note that this does not do any optimization or packing of adjacent page entries.
void FillScatterGatherList(
    IN struct _DEVICE_OBJECT  *DeviceObject,
    IN struct _IRP  *Irp,
    IN PSCATTER_GATHER_LIST  ScatterGather,
    IN PVOID  Context
    )
{
  ULONG i;
  EXECUTION_CONTEXT *pEContext =  reinterpret_cast<EXECUTION_CONTEXT *>(Context);
  I_SCATTER_LIST *pIScatterList = pEContext->pIScatterList;
  MEMORY_BLOCK *pList        = &pIScatterList->MemoryBlock;

  // Copy the system generated ScatterGatherList to our similar
  // structure to be used by the top level applications.
  for( i = 0; i < ScatterGather->NumberOfElements; i++ )
  {
    pList->dwPhysicalAddressLow = ScatterGather->Elements[i].Address.LowPart;
    pList->dwPhysicalAddressHigh = ScatterGather->Elements[i].Address.HighPart;
    pList->dwBlockSize = ScatterGather->Elements[i].Length;
    pList++;
  }

  // and pass the system list back to the caller
  pEContext->pSysScatterGatherList = ScatterGather;

  // copy the number of entries in the list.  For now this also signals to the 
  // caller that we are done.
  pIScatterList->dwNumberListEntries = ScatterGather->NumberOfElements;

}

