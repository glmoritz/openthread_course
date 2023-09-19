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

#define PORT 9608

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

void labsc_auth_init()
{
    xlabsc_auth_task_Handle = xTaskCreateStatic(
        labsc_auth_task_code,                        /* Function that implements the task. */
        "labsc_auth_task",                           /* Text name for the task. */
        labsc_auth_task_STACK_SIZE,                  /* Number of bytes in the xStack array. */
        (void *)1,                                   /* Parameter passed into the task. */
        tskIDLE_PRIORITY + labsc_auth_task_PRIORITY, /* Priority at which the task is created. */
        xlabsc_auth_task_Stack,                      /* Array to use as the task's stack. */
        &xlabsc_auth_task_struct);                   /* Variable to hold the task's data structure. */
}

#define JOINER_ERROR_NONE 0x1
#define JOINER_ERROR_SECURITY 0x2
#define JOINER_ERROR_NOT_FOUND 0x4
#define JOINER_ERROR_RESPONSE_TIMEOUT 0x8
#define JOINER_SETBITS (JOINER_ERROR_NONE | JOINER_ERROR_SECURITY | JOINER_ERROR_NOT_FOUND | JOINER_ERROR_RESPONSE_TIMEOUT)

void app_joiner_callback(otError join_err_code, void *passback)
{
    uint32_t notify = 0;
    switch (join_err_code)
    {
    case OT_ERROR_NONE:
        notify = JOINER_ERROR_NONE;
        break;
    case OT_ERROR_SECURITY:
        notify = JOINER_ERROR_SECURITY;
        break;
    case OT_ERROR_NOT_FOUND:
        notify = JOINER_ERROR_NOT_FOUND;
        break;
    case OT_ERROR_RESPONSE_TIMEOUT:
        notify = JOINER_ERROR_RESPONSE_TIMEOUT;
        break;
    default:
        notify = 0;
    }
    xTaskNotify(xlabsc_auth_task_Handle, notify, eSetBits);
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
    void *aContext=0;
    error = otIp6SetEnabled(ot_instance, true);
    if (error != OT_ERROR_NONE)
    {
        ESP_LOGE(TAG, "otIp6SetEnabled error\r\n");
        ESP_LOGE(TAG, "%d\r\n",error);
    }
    error = otLinkSetPanId(ot_instance,0xffff);
    if (error != OT_ERROR_NONE)
    {
        ESP_LOGE(TAG, "otLinkSetPanId error\r\n");
        ESP_LOGE(TAG, "%d\r\n",error);
    }
    error = otJoinerStart(ot_instance, "0HARAKR", NULL, "VENDOR", "MODEL", "SWVER", NULL, app_joiner_callback, aContext);
    if (error != OT_ERROR_NONE)
    {
        ESP_LOGE(TAG, "otJoinerStart error\r\n");
        ESP_LOGE(TAG, "%d\r\n",error);
    }
    BaseType_t xResult;
    uint32_t ulNotifiedValue;
    while (1)
    {
        xResult = xTaskNotifyWait(0x00,             /* Don't clear any notification bits on entry. */
                                  ULONG_MAX,        /* Reset the notification value to 0 on exit. */
                                  &ulNotifiedValue, /* Notified value pass out in
                                                       ulNotifiedValue. */
                                  portMAX_DELAY);   /* Block indefinitely. */

        if (xResult == pdPASS)
        {
            if ((ulNotifiedValue & JOINER_ERROR_NONE) != 0)
            {
                ESP_LOGI(TAG, "JOIN Success\r\n");
                error = otThreadSetEnabled(ot_instance, true);
                if (error != OT_ERROR_NONE)
                {
                    ESP_LOGE(TAG, "otThreadSetEnabled error\r\n");
                    ESP_LOGE(TAG, "%d\r\n",error);
                }
            }

            if ((ulNotifiedValue & JOINER_ERROR_SECURITY) != 0)
            {
                ESP_LOGE(TAG, "JOIN Error - Security\r\n");
            }

            if ((ulNotifiedValue & JOINER_ERROR_NOT_FOUND) != 0)
            {
                ESP_LOGE(TAG, "JOIN Error - Not found\r\n");
            }

            if ((ulNotifiedValue & JOINER_ERROR_RESPONSE_TIMEOUT) != 0)
            {
                ESP_LOGE(TAG, "JOIN Error - Response timeout\r\n");
            }
        }
    }

    vTaskDelete(NULL);
}
