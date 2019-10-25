/*
Driver for  USB

By Shishov  Mikhail 

Copyright 2019.


*/


#include <Dunix/kernel.h>
#include <asm/cpuinfo.h>
#include <stdarg.h>
#include <dunix/limits.h>
#include <dunix/linkage.h>
#include <dunix/stddef.h>
#include <dunix/types.h>
#include <dunix/compiler.h>
#include <dunix/bitops.h>
#include <dunix/log2.h>
#include <dunix/typecheck.h>
#include <dunix/printk.h>
#include <dunix/build_bug.h>
#include <asm/byteorder.h>
#include <asm/div64.h>
#include <asm/byteorder.h>
#include <asm/div64.h>
#include <uapi/dunix/kernel.h>
#include <asm/div64.h>


/*
struct  of  contest 

*/

typedef struct _DEVICE_CONTEXT {
WDFUSBDEVICE UsbDevice;
WDFUSBINTERFACE UsbInterface;
WDFUSBPIPE BulkReadPipe;
WDFUSBPIPE BulkWritePipe;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, DEVICE_CONTEXT);


// Link with interface 

DEFINE_GUID(GUID_DEVINTERFACE_OSRUSBFX2, // Generated using guidgen.exe
0x573e8c73, 0xcb4, 0x4471, 0xa1, 0xbf, 0xfa, 0xb2, 0x6c, 0x31, 0xd3, 0x84);
// {573E8C73-0CB4-4471-A1BF-FAB26C31D384}

status = WdfDeviceCreateDeviceInterface(device,
(LPGUID) &GUID_DEVINTERFACE_OSRUSBFX2,
NULL);// Reference String



WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig,
WdfIoQueueDispatchParallel);

ioQueueConfig.EvtIoRead = EvtIoRead;
ioQueueConfig.EvtIoWrite = EvtIoWrite;

status = WdfIoQueueCreate(device,
&ioQueueConfig,
WDF_NO_OBJECT_ATTRIBUTES,
WDF_NO_HANDLE);


// Proceing data  in  USB 


void MSC_BulkOut (void) {

BulkLen = USB_ReadEP(MSC_EP_OUT, BulkBuf);

LED_Off( LED_RD | LED_WR );
if( BulkBuf[ 0 ] == 0x01 )
{
USB_WriteEP( MSC_EP_IN, (unsigned char*)aBuff_1, sizeof( aBuff_1 ) );
LED_On( LED_RD );
}
else
if( BulkBuf[ 0 ] == 0x02 )
{
USB_WriteEP( MSC_EP_IN, (unsigned char*)aBuff_2, sizeof( aBuff_1 ) );
LED_On( LED_WR );
}
}



