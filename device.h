/**************************************************************************

    Foresight Imaging WDM AVStream Driver

    Copyright (c) 2008 Foresight Imaging, LLC

    File:

        device.h

    Abstract:

        Device level information for the Foresight Imaging frame grabbers
        
    History:

        created 12/15/2008

**************************************************************************/
#pragma once
#include "grabber.h"

extern "C" {
//#include <Ntifs.h>
#include <ntddk.h>

// Needed to define this since the one in ntddk.h isn't seen?? 
NTKERNELAPI PHYSICAL_ADDRESS MmGetPhysicalAddress( __in PVOID BaseAddress );

HANDLE PsGetCurrentProcessId(void);
HANDLE PsGetCurrentThreadId(void);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
  __in HANDLE ProcessId, __out PEPROCESS *Process);
 
}


#if DBG
	#define SHOW_DECORATED_DEBUG
#endif

#if defined SHOW_DECORATED_DEBUG

void DecoratedDebug(char* pszFunc, char* pszSerial, char* pszFormat, ...);

//#define DECORATED_DEBUG(pszSerial, pszFormat, ...) \
																									//{ \
//  HANDLE _hProcessID = PsGetCurrentProcessId(); \
//  ULONGLONG _qwProcessID = (ULONGLONG)_hProcessID; \
//  HANDLE _hThreadID = PsGetCurrentThreadId(); \
//  ULONGLONG _qwThreadID = (ULONGLONG)_hThreadID; \
//  sprintf_s(__szDebugString, #pszFormat, __VA_ARGS__); \
//  if(sizeof(void*) == 4) \
//    sprintf_s(__szOutputString, "[%4I64x] -- IdeaDrv32.sys   [TID:%4I64x] - [SN:%5s] %s\r\n", _qwProcessID, _qwThreadID, pszSerial, __szDebugString); \
//  else \
//    sprintf_s(__szOutputString, "[%4I64x] -- IdeaDrv64.sys   [TID:%4I64x] - [SN:%5s] %s\r\n", _qwProcessID, _qwThreadID, pszSerial, __szDebugString); \
//    FSI_LogMessage( __szOutputString );\
//    DbgPrint((__szOutputString);\
//}

//LARGE_INTEGER Now; \
//LARGE_INTEGER ElapsedMicroseconds; \
//DWORD dwms; \
//DWORD dwus; \
//Now = KeQueryPerformanceCounter(NULL); \
//ElapsedMicroseconds.QuadPart = Now.QuadPart - PCStartingTime.QuadPart; \
//ElapsedMicroseconds.QuadPart *= 1000000; \
//ElapsedMicroseconds.QuadPart /= PCFrequency.QuadPart; \
//dwms = (DWORD)(ElapsedMicroseconds.QuadPart / 1000); \
//dwus = (DWORD)(ElapsedMicroseconds.QuadPart - (dwms * 1000); \
//sprintf_s(__szDebugString, #pszFormat, __VA_ARGS__); \
//sprintf_s(__szOutputString, "[%08d.%03dms] %s\r\n", dwms, dwus, __szDebugString); \
//FSI_LogMessage(__szOutputString); \
//DbgPrint((__szOutputString); \
//KdPrint((__szOutputString);\

#define DECORATED_DEBUG(pszSerial, pszFormat, ...) \
{ \
	DecoratedDebug(__FUNCSIG__, (char*)pszSerial, #pszFormat, __VA_ARGS__); \
}


#else
	void DecoratedDebug(char* pszFunction, char* pszSerial, char* pszFormat, ...);

	#define DECORATED_DEBUG(pszSerial, pszFormat, ...) \
	{ \
	  \
	  if (KeGetCurrentIrql() <= PASSIVE_LEVEL) \
	  { \
		  DecoratedDebug(__FUNCSIG__, (char*)pszSerial, #pszFormat, __VA_ARGS__); \
	  } \
	}
#endif

// pool tag for allocations
#define FSI_POOL_TAG (ULONG) 'eroF'

// Device IDs - for now only the 2 families to be supported
#define DEVICE_ID_ACCUSTREAM_170_PLUS  (0x0090)
#define DEVICE_ID_ACCUSTREAM_75_PLUS   (0x0091)
#define DEVICE_ID_ACCUSTREAM_50_PLUS   (0x0092)
#define DEVICE_ID_ACCUSTREAM_205A      (0x0084)
#define DEVICE_ID_ACCUSTREAM_50        (0x0085)
#define DEVICE_ID_ACCUSTREAM_75        (0x0086)
#define DEVICE_ID_ACCUSTREAM_50A       (0x0088)
#define DEVICE_ID_ACCUSTREAM_75A       (0x0089)
#define DEVICE_ID_ACCUSTREAM_VDR       (0x0087)
#define DEVICE_ID_ACCUSTREAM_170       (0x0080)
#define DEVICE_ID_ACCUSTREAM_XPRSS     (0x0020)  /* this may be the 170, 50 or 75 */
#define DEVICE_ID_ACCUSTREAM_XPRSS_HD  (0x0024)  /* this may be the HD+, 50+ or 75+ */
#define DEVICE_ID_ACCUSTREAM_XPRSS_HDC (0x0025)  /* this may be the HD+C, 50+C or 75+C */
#define DEVICE_ID_ACCUSTREAM_XPRSS_1000 (0x0030)  

// ported structures from the original SYS driver
typedef short BoardHandle;
typedef short HIDEF_TYPE;
// Wanted to reduce this to 8, but cant because of the diag
#define HIDEF_MAX_BOARDS  (15)

typedef struct {
  HIDEF_TYPE      nType;     /* HIDEF_PLUS, HIDEF_ACCURA, etc.       */
  unsigned short  wID;       /* ISA Base IO address or PCI slot #.   */
  unsigned short  wIO;       /* Base IO address.                     */
  char            cID;       /* Character ID assigned in registry.   */
  char            cResv;     /* Forcing WORD alignment.              */
  char            szSerial[8]; /* ASCII Serial number, if available. */
  BoardHandle     bh;        /* Handle if claimed by this VM, else 0.*/
  short           bClaim;    /* True if claimed by any process.      */
  unsigned long   dwFeatures;/* Features available on this board.    */
} HD_sBoard;
typedef struct {
  unsigned long   e;
  unsigned short  wRev;
  short           nBrdCount;
  short           nBrdList;
  unsigned short  w32BitDriver;   /* Are wwe using a 32 bit or 64 bit driver */
  unsigned long   dwFragDMA;
  unsigned long   dwFragHisto;
  HD_sBoard       bra[HIDEF_MAX_BOARDS];
} HD_sReport;

/*
// Structure for IOCTL_HIDEF_CLAIM parameters.
*/

typedef struct {
  unsigned long  e;          /* Out: IOCTL_HIDEF_CLAIM return status.*/
  short          nMode;      /* In:  Type of claim request.          */
  unsigned short wSelect;    /* In:  Board selection.                */
  BoardHandle    bh;         /* In:  BoardHandle assigned by library */
  unsigned short wResv;      /*      Reserved.                       */
} HDDRV_IO_CLAIM;


typedef struct {
  ULONG dwPhysicalAddressLow;   /* Physical address of block */
  ULONG dwPhysicalAddressHigh;  /* High part of physical address */
  ULONG dwBlockSize;            /* Size in bytes of block */
} MEMORY_BLOCK;

typedef struct {
//  void *pBuffer;                /* Pointer to the buffer to lock */
  ULONGLONG pBuffer;            /* Pointer to the buffer to lock */
  ULONG dwBufferSize;           /* Size of the buffer to lock in bytes */
  ULONG dwNumberListEntries;    /* # of scatter list structs after this struct */
  ULONG dwMemHandle;            /* Memory handle of the locked buffer */
  MEMORY_BLOCK MemoryBlock;     /* The first memory block sructure of list */
} I_SCATTER_LIST;


class   CFrameGrabber;  // forward reference
class   CCapturePin;


class CCaptureDevice 
{

private:

  //
  // The AVStream device we're associated with.
  //
  PKSDEVICE m_Device;

  //
  // Number of pins with resources acquired.  This is used as a locking
  // mechanism for resource acquisition on the device.
  //
  LONG m_PinsWithResources;

  //
  // The number of map registers returned from IoGetDmaAdapter().
  //
  ULONG m_NumberOfMapRegisters;
  ULONG m_NumberOfMapRegistersForCaptureDescriptors;

  //
  BUS_INTERFACE_STANDARD m_BusInterface;    // So I can read the PCI Config space

  //
  // Cleanup():
  //
  // This is the free callback for the bagged capture device.  Not providing
  // one will call ExFreePool, which is not what we want for a constructed
  // C++ object.  This simply deletes the capture device.
  //
  static void Cleanup ( IN CCaptureDevice *CapDevice  )
  {
    delete CapDevice;
  }

  static void CleanupGrabber ( IN CFrameGrabber *pGrabber  )
  {
    delete pGrabber;
  }


  //
  // PnpStart():
  //
  // This is the Pnp start routine for our simulated hardware.  Note that
  // DispatchStart bridges to here in the context of the CCaptureDevice.
  //
  NTSTATUS  PnpStart (
      IN PCM_RESOURCE_LIST TranslatedResourceList,
      IN PCM_RESOURCE_LIST UntranslatedResourceList
      );

  NTSTATUS  InitializeResources(
        IN PCM_RESOURCE_LIST pTranslatedResourceList 
      );

  //
  // PnpQueryStop():
  //
  // This is the Pnp query stop routine for our simulated hardware.  Note that
  // DispatchQueryStop bridges to here in the context of the CCaptureDevice.
  //
  NTSTATUS PnpQueryStop();

  //
  // PnpCancelStop():
  //
  // This is the Pnp cancel stop routine for our simulated hardware.  Note that
  // DispatchCancelStop bridges to here in the context of the CCaptureDevice.
  //
  void PnpCancelStop();

  //
  // PnpStop():
  //
  // This is the Pnp stop routine for our simulated hardware.  Note that
  // DispatchStop bridges to here in the context of the CCaptureDevice.
  //
  void PnpStop ();

  //
  // PnpQueryRemove():
  //
  // This is the Pnp stop routine for our simulated hardware.  Note that
  // DispatchQueryRemove bridges to here in the context of the CCaptureDevice.
  //
  NTSTATUS PnpQueryRemove();

  //
  // PnpCancelRemove():
  //
  // This is the Pnp cancel remove routine for our simulated hardware.  Note that
  // DispatchCancelRemove bridges to here in the context of the CCaptureDevice.
  //
  void PnpCancelRemove();

  //
  // PnpRemove():
  //
  // This is the Pnp remove routine for our simulated hardware.  Note that
  // DispatchRemove bridges to here in the context of the CCaptureDevice.
  //
  void PnpRemove();

  //
  // PnpSurpriseRemoval():
  //
  // This is the Pnp Surprise Removal routine for our simulated hardware.  Note that
  // DispatchStop bridges to here in the context of the CCaptureDevice.
  //
  //void PnpSurpriseRemoval();

public:

  // Frame grabber pointer - we'll figure out exactly what kind of 
  // grabber at run time
  CFrameGrabber  *m_pGrabber;

  // The reason for the PnP Stop must be recorded so we can properly react to a surprise removal
  PNP_STOP_TYPE m_PnPStopType = NORMAL_PNP_STOP;

    //
  // The Dma adapter object we acquired through IoGetDmaAdapter() during
  // Pnp start.  This must be initialized with AVStream in order to perform
  // Dma directly into the capture buffers.
  //
  PADAPTER_OBJECT m_DmaAdapterObjectForCaptureDescriptors;
  PADAPTER_OBJECT m_DmaAdapterObject;

  //
  // CCaptureDevice():
  //
  // The capture device class constructor.  Since everything should have
  // been zero'ed by the new operator, don't bother setting anything to
  // zero or NULL.  Only initialize non-NULL, non-0 fields.
  //
  CCaptureDevice ( IN PKSDEVICE Device ) : m_Device (Device)
  {
    //DECORATED_DEBUG("", "CCaptureDevice::CCaptureDevice()");
    m_pVideoInfoHeader = 0;
    m_PinsWithResources = 0;
  }

  //
  // ~CCaptureDevice():
  //
  // The capture device destructor.
  //
  ~CCaptureDevice()
  {
  }

  //
  // DispatchPnpAdd():
  //
  // This is the Pnp Add Device dispatch for the capture device.  It creates
  // the CCaptureDevice and associates it with the device via the bag.
  //
  static
  NTSTATUS
  DispatchPnpAdd (
      IN PKSDEVICE Device
      );

  
  //
  // DispatchPnpStart():
  //
  // This is the Pnp Start dispatch for the capture device.  It simply
  // bridges to PnpStart() in the context of the CCaptureDevice.
  //
  static
  NTSTATUS
  DispatchPnpStart (
      IN PKSDEVICE Device,
      IN PIRP Irp,
      IN PCM_RESOURCE_LIST TranslatedResourceList,
      IN PCM_RESOURCE_LIST UntranslatedResourceList
      )
  {
	  DECORATED_DEBUG("", "VERSION 59");
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnpStart() VERSION #59");

	  //(reinterpret_cast <CCaptureDevice *> (Device->Context))->m_PnPStopType = NORMAL_PNP_STOP;

      return 
      (reinterpret_cast <CCaptureDevice *> (Device->Context))->PnpStart (
              TranslatedResourceList,
              UntranslatedResourceList
              );
  }

  static NTSTATUS DispatchPnPPostStart(
	  _In_ PKSDEVICE Device)
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnPPostStart()");

	  return STATUS_SUCCESS;
  }

  /*static NTSTATUS DispatchPnPQueryCaps(
	  _In_ PKSDEVICE Device,
	  _In_ PIRP Irp,
	  _Inout_ PDEVICE_CAPABILITIES Capabilities)
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnPQueryCaps()");

	  //DECORATED_DEBUG(m_szSerialNo, "width = %d, height = %d, Size = %d Compress = %x, AvgTime = %I64d",
	  //	  );

	  return STATUS_SUCCESS;
  }*/

  /*static NTSTATUS DispatchPnPQueryPower(
	  _In_ PKSDEVICE Device,
	  _In_ PIRP Irp,
	  _In_ DEVICE_POWER_STATE DeviceTo,
	  _In_ DEVICE_POWER_STATE DeviceFrom,
	  _In_ SYSTEM_POWER_STATE SystemTo,
	  _In_ SYSTEM_POWER_STATE SystemFrom,
	  _In_ POWER_ACTION Action
  )
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnPQueryPower()");

	  return STATUS_SUCCESS;
  };*/

  /*static void DispatchPnPSetPower(
	  _In_ PKSDEVICE Device,
	  _In_ PIRP Irp,
	  _In_ DEVICE_POWER_STATE To,
	  _In_ DEVICE_POWER_STATE From
  )
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnPSetPower()");
  }*/

  /*static NTSTATUS DispatchPnPQueryInterface(
	  _In_ PKSDEVICE Device,
	  _In_ PIRP Irp
  )
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnPQueryInterface()");

	  return STATUS_SUCCESS;
  }*/

  //
  // DispatchPnpQueryStop():
  //
  // This is the Pnp query stop dispatch for the capture device.  It simply
  // bridges to PnpStop() in the context of the CCaptureDevice.
  //
  static NTSTATUS  DispatchPnpQueryStop(
	  IN PKSDEVICE Device,
	  IN PIRP Irp
  )
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnpQueryStop()");

	  if (Device)
	  {
		  if (Device->Context)
			  return (reinterpret_cast <CCaptureDevice *> (Device->Context))->PnpQueryStop();
	  }

	  // null device and/or Context, just pass success as we have nothing to do here
	  return STATUS_SUCCESS;
  }

  //
  // DispatchPnpCancelStop():
  //
  // This is the Pnp cancel stop dispatch for the capture device.  It simply
  // bridges to PnpCancelStop() in the context of the CCaptureDevice.
  //
  static void  DispatchPnpCancelStop(
	  IN PKSDEVICE Device,
	  IN PIRP Irp
  )
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnpCancelStop()");

	  if (Device)
	  {
		  if (Device->Context)
			  (reinterpret_cast <CCaptureDevice *> (Device->Context))->PnpCancelStop();
	  }
  }

  //
  // DispatchPnpStop():
  //
  // This is the Pnp stop dispatch for the capture device.  It simply
  // bridges to PnpStop() in the context of the CCaptureDevice.
  //
  static void  DispatchPnpStop (
      IN PKSDEVICE Device,
      IN PIRP Irp
      )
  {
	DECORATED_DEBUG("", "CCaptureDevice::DispatchPnpStop()");

    if( Device )
    {
      if( Device->Context )
        (reinterpret_cast <CCaptureDevice *> (Device->Context))->PnpStop ();
    }
  }

  //
  // DispatchPnpQueryRemove():
  //
  // This is the Pnp query remove dispatch for the capture device.  It simply
  // bridges to PnpQueryRemove() in the context of the CCaptureDevice.
  //
  static NTSTATUS  DispatchPnpQueryRemove(
	  IN PKSDEVICE Device,
	  IN PIRP Irp
  )
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnpQueryRemove()");

	  if (Device)
	  {
		  if (Device->Context)
		  {
			  //return (reinterpret_cast <CCaptureDevice *> (Device->Context))->PnpQueryRemove();
			  NTSTATUS localStat = (reinterpret_cast <CCaptureDevice *> (Device->Context))->PnpQueryRemove();

			  /*if (localStat == STATUS_SUCCESS)
			  {
				  Irp->IoStatus.Status = STATUS_SUCCESS;
			  }*/

			  return localStat;
		  }
	  }

	  // null device and/or Context, just pass success as we have nothing to do here
	  //Irp->IoStatus.Status = STATUS_SUCCESS;

	  return STATUS_SUCCESS;
  }

  //
  // DispatchPnpCancelRemove():
  //
  // This is the Pnp cancel remove dispatch for the capture device.  It simply
  // bridges to PnpCancelRemove() in the context of the CCaptureDevice.
  //
  static void  DispatchPnpCancelRemove(
	  IN PKSDEVICE Device,
	  IN PIRP Irp
  )
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnpCancelRemove()");

	  if (Device)
	  {
		  if (Device->Context)
			  (reinterpret_cast <CCaptureDevice *> (Device->Context))->PnpCancelRemove();
	  }
  }

  //
  // DispatchPnpRemove():
  //
  // This is the Pnp remove dispatch for the capture device.  It simply
  // bridges to PnpRemove() in the context of the CCaptureDevice.
  //
  static void  DispatchPnpRemove(
	  IN PKSDEVICE Device,
	  IN PIRP Irp
  )
  {
	  DECORATED_DEBUG("", "CCaptureDevice::DispatchPnpRemove()");

	  if (Device)
	  {
		  if (Device->Context)
			  (reinterpret_cast <CCaptureDevice *> (Device->Context))->PnpRemove();
	  }
  }

//
// DispatchPnpSurpriseRemoval():
//
// This is the Pnp Surprise Removal dispatch for the capture device.  It simply
// bridges to DispatchPnpSurpriseRemoval() in the context of the CCaptureDevice.
//
static void  DispatchPnpSurpriseRemoval(
	IN PKSDEVICE Device,
	IN PIRP Irp
	)
{
	DECORATED_DEBUG("", "CCaptureDevice::DispatchPnpSurpriseRemoval()");

	if (Device)
	{
		if (Device->Context)
		{
			//(reinterpret_cast <CCaptureDevice *> (Device->Context))->m_PnPStopType = SURPRISE_PNP_STOP;
			(reinterpret_cast <CCaptureDevice *> (Device->Context))->PnpStop();
		}
	}
}
//
  // AcquireHardwareResources():
  //
  // Called to acquire hardware resources for the device based on a given
  // video info header.  This will fail if another object has already
  // acquired hardware resources since we emulate a single capture
  // device.
  //
  NTSTATUS  AcquireHardwareResources (
      IN PKS_VIDEOINFO VideoInfoHeader
      );

  //
  // ReleaseHardwareResources():
  //
  // Called to release hardware resources for the device.
  //
  void  ReleaseHardwareResources ( );

  //
  // Start():
  //
  // Called to start the hardware simulation.  This causes us to simulate
  // interrupts, simulate filling buffers with synthesized data, etc...
  //
  NTSTATUS Start();

  //
  // Pause():
  //
  // Called to pause or unpause the hardware simulation.  This will be
  // indentical to a start or stop but it will not reset formats and 
  // counters.
  //
  NTSTATUS Pause ( IN BOOLEAN Pausing );

  //
  // Stop():
  //
  // Called to stop the hardware simulation.  This causes interrupts to
  // stop issuing.  When this call returns, the "fake" hardware has
  // stopped accessing all s/g buffers, etc...
  //
  NTSTATUS Stop();

  //
  // ProgramScatterGatherMappings():
  //
  // Called to program the hardware simulation's scatter / gather table.
  // This synchronizes with the "fake" ISR and hardware simulation via
  // a spinlock.
  //
//  ULONG  ProgramScatterGatherMappings ();


  NTSTATUS Snap();

  //
  NTSTATUS FsiGetStandardInterface(
    IN PDEVICE_OBJECT DeviceObject,
    OUT PBUS_INTERFACE_STANDARD BusInterface
    );

  
  _Dispatch_type_(IRP_MJ_CREATE)
	  static NTSTATUS CCaptureDevice::DispatchCreate(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
  );

  _Dispatch_type_(IRP_MJ_CLOSE)
	  static NTSTATUS CCaptureDevice::DispatchClose(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
  );

  _Dispatch_type_(IRP_MJ_CLEANUP)
	  static NTSTATUS CCaptureDevice::DispatchCleanup(
	  IN  PDEVICE_OBJECT  DeviceObject,
	  IN  PIRP            Irp
  );
  
  _Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
  static NTSTATUS DispatchControl(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    );

  DWORD GetDataFormat() { 
    if( m_pVideoInfoHeader != 0 )
      return  m_pVideoInfoHeader->bmiHeader.biCompression;
    else
       return 0;
  }
  
  PDEVICE_OBJECT GetDeviceObject() { return m_Device->PhysicalDeviceObject; }

  void  GetBasePointers( BASEPTRINFO *pBasePtrs );
  void  DoReport(
            HD_sReport  *phrptIn, 
            short       nIn, 
            HD_sReport  *phrptOut,
            short       nOut, 
            ULONG       *pdwRet
       );
  void Claim( 
      HDDRV_IO_CLAIM   *pClaimIn, 
      short            nIn, 
      HDDRV_IO_CLAIM   *pClaimOut,
      short            nOut,
      ULONG            *pdwRet);

  void UnClaim();

  void SavePCIConfig();
  void RestorePCIConfig();
  
PMDL MyIoAllocateMdl(PVOID pBuffer, ULONG dwBufferSize, BOOLEAN SecondaryBuffer,
                   BOOLEAN ChargeQuota, PIRP Irp);

public:
  PVOID               pCaptureDescriptors = 0;      // contiguous buffer used for DMA descriptors
  PVOID               pUserMappedCaptureDescriptors;  // above as mapped into user space
  PHYSICAL_ADDRESS    CaptureDescriptorsPhysAddress; // physical address of the above
  PMDL                pmdlCaptureDescriptors;        // MDL for user mapped common buffer
  ULONG               CaptureDescriptorsSize;        // number of bytes allocated for common buffer

  PVOID               pPreviewDescriptors = 0;      // contiguous buffer used for DMA descriptors
  PHYSICAL_ADDRESS    PreviewDescriptorsPhysAddress; // physical address of the above

  PVOID               pCompressDescriptors = 0;      // contiguous buffer used for DMA descriptors
  PHYSICAL_ADDRESS    CompressDescriptorsPhysAddress; // physical address of the above

  BYTE                PCIConfig[64];           // PCI config space for save/restore

  PMAILBOX			  pMailBox = 0;                // contiguous buffer used for proxy mailbox
  PMDL                pmdlMailBox;             // MDL for proxy mailbox
	PMAILBOX         pUserMappedMailBox;      // above as mapped into user space
  int                 m_nProcessCount;
  PROCESS_LIST_ENTRY  m_ProcessList[32];
  //
  // The video info header we're basing hardware settings on.  The pin
  // provides this to us when acquiring resources and must guarantee its
  // stability until resources are released.
  //
  PKS_VIDEOINFO m_pVideoInfoHeader;

  //
  // The last reading of mappings completed.
  //
  ULONG m_LastMappingsCompleted;
  
  HANDLE m_hDriverEvents[NUM_DRIVER_EVENTS];

};

