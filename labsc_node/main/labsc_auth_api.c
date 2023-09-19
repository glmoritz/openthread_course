/* BSD Socket API Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_openthread.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include <openthread/cli.h>
#include <openthread/dataset.h>
#include <openthread/dns_client.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/logging.h>
#include <openthread/mesh_diag.h>
#include <openthread/netdata.h>
#include <openthread/ping_sender.h>
#include <openthread/sntp.h>
#if OPENTHREAD_CONFIG_TCP_ENABLE && OPENTHREAD_CONFIG_CLI_TCP_ENABLE
#include <openthread/tcp.h>
#endif
#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/udp.h>

#include "labsc_auth_api.h"

#define PORT 9608

AUTH_STATE gAuthMachineState = AUTH_RESET;

static const char *TAG = "labsc auth";

// /*----------- labsc_auth_task MEMORY-------------*/

/* ESP-IDF FreeRTOS also changes the units of ulStackDepth in the task creation functions.
Task stack sizes in Vanilla FreeRTOS are specified in number of words, whereas in ESP-IDF FreeRTOS,
the task stack sizes are specified in bytes. */
#define labsc_auth_task_STACK_SIZE 4096
#define labsc_auth_task_PRIORITY 1
/* Structure that will hold the TCB of the task being created. */
StaticTask_t xlabsc_auth_task_struct;
/* Buffer that the task being created will use as its stack.  Note this is
an array of StackType_t variables.  The size of StackType_t is dependent on
the RTOS port. */
StackType_t xlabsc_auth_task_Stack[labsc_auth_task_STACK_SIZE / sizeof(StackType_t)];
extern void xlabsc_auth_task_code(void *aContext);

TaskHandle_t xlabsc_auth_task_Handle = NULL;
void labsc_auth_task_code(void *pvParameters);

// /*----------- labsc_auth_event_handler_task MEMORY-------------*/

/* ESP-IDF FreeRTOS also changes the units of ulStackDepth in the task creation functions.
Task stack sizes in Vanilla FreeRTOS are specified in number of words, whereas in ESP-IDF FreeRTOS,
the task stack sizes are specified in bytes. */
#define labsc_auth_event_handler_task_STACK_SIZE 4096
#define labsc_auth_event_handler_task_PRIORITY 1
/* Structure that will hold the TCB of the task being created. */
StaticTask_t xlabsc_auth_event_handler_task_struct;
/* Buffer that the task being created will use as its stack.  Note this is
an array of StackType_t variables.  The size of StackType_t is dependent on
the RTOS port. */
StackType_t xlabsc_auth_event_handler_task_Stack[labsc_auth_event_handler_task_STACK_SIZE / sizeof(StackType_t)];


TaskHandle_t xlabsc_auth_event_handler_task_Handle = NULL;
void labsc_auth_event_handler_task_code(void *pvParameters);


// /*----------- auth event timer MEMORY-------------*/

/* An array to hold handles to the created timers. */
 TimerHandle_t xAuthEventTimerHandler;

 /* An array of StaticTimer_t structures, which are used to store
 the state of each created timer. */
 StaticTimer_t xAuthEventTimerBuffer;


// /*----------- auth state semaphore MEMORY-------------*/
SemaphoreHandle_t xAuthStateSemaphoreHandle = NULL;
StaticSemaphore_t xAuthStateSemaphoreBuffer;



 /* Define a callback function that will be used by multiple timer
 instances.  The callback function does nothing but count the number
 of times the associated timer expires, and stop the timer once the
 timer has expired 10 times.  The count is saved as the ID of the
 timer. */
 void vAuthEventTimerCallback(TimerHandle_t pxTimer)
 {
     xTaskNotify(xlabsc_auth_event_handler_task_Handle, AUTH_EVENT_TIME, eSetBits);
 }

BaseType_t AuthTimeNotifyAfterMs(uint32_t ms)
{
    xTimerChangePeriod( xAuthEventTimerHandler, ms / portTICK_PERIOD_MS ,  portMAX_DELAY);
    xTimerStart( xAuthEventTimerHandler, portMAX_DELAY );
    return pdPASS;
}

char gErrorMSG[128];

BaseType_t labsc_auth_api_init()
{
    xAuthEventTimerHandler = xTimerCreateStatic(/* Just a text name, not used by the RTOS
                                       kernel. */
                                                "Auth Event Timer",
                                                /* The timer period in ticks, must be
                                                greater than 0. */
                                                100,
                                                /* The timers will auto-reload themselves
                                                when they expire. */
                                                pdFALSE,
                                                /* The ID is used to store a count of the
                                                number of times the timer has expired, which
                                                is initialised to 0. */
                                                (void *)0,
                                                /* Each timer calls the same callback when
                                                it expires. */
                                                vAuthEventTimerCallback,
                                                /* Pass in the address of a StaticTimer_t
                                                variable, which will hold the data associated with
                                                the timer being created. */
                                                &(xAuthEventTimerBuffer));

    /* Create a binary semaphore without using any dynamic memory
    allocation.  The semaphore's data structures will be saved into
    the xSemaphoreBuffer variable. */
    xAuthStateSemaphoreHandle = xSemaphoreCreateBinaryStatic(&xAuthStateSemaphoreBuffer);
    if(xAuthStateSemaphoreHandle)
        xSemaphoreGive(xAuthStateSemaphoreHandle);

    xlabsc_auth_task_Handle = xTaskCreateStatic(
        labsc_auth_task_code,                        /* Function that implements the task. */
        "labsc_auth_task",                           /* Text name for the task. */
        labsc_auth_task_STACK_SIZE,                  /* Number of bytes in the xStack array. */
        (void *)1,                                   /* Parameter passed into the task. */
        tskIDLE_PRIORITY + labsc_auth_task_PRIORITY, /* Priority at which the task is created. */
        xlabsc_auth_task_Stack,                      /* Array to use as the task's stack. */
        &xlabsc_auth_task_struct);                   /* Variable to hold the task's data structure. */

    xlabsc_auth_event_handler_task_Handle = xTaskCreateStatic(
        labsc_auth_event_handler_task_code,                        /* Function that implements the task. */
        "labsc_auth_event_handler_task",                           /* Text name for the task. */
        labsc_auth_event_handler_task_STACK_SIZE,                  /* Number of bytes in the xStack array. */
        (void *)1,                                                 /* Parameter passed into the task. */
        tskIDLE_PRIORITY + labsc_auth_event_handler_task_PRIORITY, /* Priority at which the task is created. */
        xlabsc_auth_event_handler_task_Stack,                      /* Array to use as the task's stack. */
        &xlabsc_auth_event_handler_task_struct);                   /* Variable to hold the task's data structure. */

    if (xlabsc_auth_task_Handle && xlabsc_auth_event_handler_task_Handle && xAuthEventTimerHandler)
        return pdPASS;
    else
    {
        return pdFAIL;
    }
}

// calls to this function must be protected by semaphore xAuthStateSemaphoreHandle
void SetAuthState(AUTH_STATE state)
{
    gAuthMachineState = state;
    xTaskNotify(xlabsc_auth_task_Handle, 0x1, eSetBits);    
}

void app_joiner_callback(otError join_err_code, void *passback)
{
    uint32_t notify = 0;
    switch (join_err_code)
    {
    case OT_ERROR_NONE:
        notify = AUTH_EVENT_JOINER_ERROR_NONE;
        break;
    case OT_ERROR_SECURITY:
        notify = AUTH_EVENT_JOINER_ERROR_SECURITY;
        break;
    case OT_ERROR_NOT_FOUND:
        notify = AUTH_EVENT_JOINER_ERROR_NOT_FOUND;
        break;
    case OT_ERROR_RESPONSE_TIMEOUT:
        notify = AUTH_EVENT_JOINER_ERROR_RESPONSE_TIMEOUT;
        break;
    default:
        notify = 0;
    }
    xTaskNotify(xlabsc_auth_event_handler_task_Handle, notify, eSetBits);
}

void labsc_auth_event_handler_task_code(void *pvParameters)
{
    BaseType_t xResult;
    uint32_t ulNotifiedValue;

    while (1)
    {
        xResult = xTaskNotifyWait(0x00,             /* Don't clear any notification bits on entry. */
                                  ULONG_MAX,        /* Reset the notification value to 0 on exit. */
                                  &ulNotifiedValue, /* Notified value pass out in
                                                       ulNotifiedValue. */
                                  portMAX_DELAY);   /* Block indefinitely. */

        xSemaphoreTake(xAuthStateSemaphoreHandle, portMAX_DELAY);
        if (xResult == pdPASS)
        {
            switch (gAuthMachineState)
            {
            case AUTH_RESET:
            {
                SetAuthState(AUTH_CONFIGURING);
                break;
            }
            case AUTH_CONFIGURING:
            {
                
                break;
            }
            case AUTH_JOINING:
            {
                if ((ulNotifiedValue & AUTH_EVENT_JOINER_ERROR_NONE) != 0)
                {
                    SetAuthState(AUTH_JOINED);
                }

                if ((ulNotifiedValue & AUTH_EVENT_JOINER_ERROR_SECURITY) != 0)
                {
                    strcpy(gErrorMSG,"JOIN Error - Security\r\n");
                    SetAuthState(AUTH_ERROR);                    
                }

                if ((ulNotifiedValue & AUTH_EVENT_JOINER_ERROR_NOT_FOUND) != 0)
                {
                    strcpy(gErrorMSG,"JOIN Error - Not found\r\n");
                    SetAuthState(AUTH_ERROR);                                        
                }

                if ((ulNotifiedValue & AUTH_EVENT_JOINER_ERROR_RESPONSE_TIMEOUT) != 0)
                {
                    strcpy(gErrorMSG, "JOIN Error - Response timeout\r\n");
                    SetAuthState(AUTH_ERROR);                              
                }
                break;
            }
            default:
                break;
            }
        }
        xSemaphoreGive(xAuthStateSemaphoreHandle);
    }
}



void labsc_auth_task_code(void *pvParameters)
{
    // error = otJoinerStart(GetInstancePtr(),
    //                       aArgs[0].GetCString(),           // aPskd
    //                       aArgs[1].GetCString(),           // aProvisioningUrl (`nullptr` if aArgs[1] is empty)
    //                       PACKAGE_NAME,                    // aVendorName
    //                       OPENTHREAD_CONFIG_PLATFORM_INFO, // aVendorModel
    //                       PACKAGE_VERSION,                 // aVendorSwVersion
    //                       nullptr,                         // aVendorData
    //                       &Joiner::HandleCallback, this);

    otError error;
    struct otInstance *ot_instance = esp_openthread_get_instance();
    void *aContext = 0;
    BaseType_t xResult;
    uint32_t ulNotifiedValue;
    AuthTimeNotifyAfterMs(100);
    while (1)
    {
        xResult = xTaskNotifyWait(0x00,             /* Don't clear any notification bits on entry. */
                                  ULONG_MAX,        /* Reset the notification value to 0 on exit. */
                                  &ulNotifiedValue, /* Notified value pass out in
                                                       ulNotifiedValue. */
                                  portMAX_DELAY);   /* Block indefinitely. */

        xSemaphoreTake(xAuthStateSemaphoreHandle, portMAX_DELAY);
        if (xResult == pdPASS)
        {
            switch (gAuthMachineState)
            {
            case AUTH_RESET:
            {
                AuthTimeNotifyAfterMs(1000);
                break;
            }
            case AUTH_CONFIGURING:
            {
                error = otIp6SetEnabled(ot_instance, true);
                if (error != OT_ERROR_NONE)
                {
                    ESP_LOGE(TAG, "otIp6SetEnabled error\r\n");
                    ESP_LOGE(TAG, "%d\r\n", error);
                    SetAuthState(AUTH_RESET);
                    break;
                }
                
                error = otLinkSetPanId(ot_instance, 0xffff);
                if (error != OT_ERROR_NONE)
                {
                    ESP_LOGE(TAG, "otLinkSetPanId error\r\n");
                    ESP_LOGE(TAG, "%d\r\n", error);
                    SetAuthState(AUTH_RESET);
                    break;
                }
                else
                {
                    SetAuthState(AUTH_JOINING);
                }                
                break;
            }
            case AUTH_JOINING:
            {
                error = otJoinerStart(ot_instance, "0HARAKR", NULL, "VENDOR", "MODEL", "SWVER", NULL, app_joiner_callback, aContext);
                if (error != OT_ERROR_NONE)
                {
                    ESP_LOGE(TAG, "otJoinerStart error\r\n");
                    ESP_LOGE(TAG, "%d\r\n", error);
                    SetAuthState(AUTH_RESET);
                    break;
                }    
                break;            
            }
            case AUTH_JOINED:
            {
                ESP_LOGI(TAG, "JOIN Success\r\n");
                error = otThreadSetEnabled(ot_instance, true);
                if (error != OT_ERROR_NONE)
                {
                    ESP_LOGE(TAG, "otThreadSetEnabled error\r\n");
                    ESP_LOGE(TAG, "%d\r\n", error);
                    SetAuthState(AUTH_RESET);
                    break;
                }
                break;
            }
            case AUTH_ERROR:
            {
                ESP_LOGE(TAG, "%s",(gErrorMSG));
                SetAuthState(AUTH_RESET);
                break;
            }
            default:

                break;
            }
        }
        xSemaphoreGive(xAuthStateSemaphoreHandle);
    }

    vTaskDelete(NULL);
}
