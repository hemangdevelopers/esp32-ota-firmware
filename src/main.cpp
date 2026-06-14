#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <ArduinoOTA.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <ArduinoJson.h>
#include <WiFiManager.h>
#include <Preferences.h>

#include "esp_wifi.h"
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"

#include "version.h"

// --------------------------------------------------
// RTOS Task Handles
// --------------------------------------------------
TaskHandle_t mqttTaskHandle = NULL;
TaskHandle_t sensorTaskHandle = NULL;
TaskHandle_t otaTaskHandle    = NULL;
TaskHandle_t wifiTaskHandle   = NULL;

SemaphoreHandle_t mqttMutex;

// --------------------------------------------------
// Global State
// --------------------------------------------------
unsigned long lastReconnectAttempt = 0;
int           wifiFailureCount     = 0;
bool          portalRunning        = false;

WiFiManager wm;

// --------------------------------------------------
// DHT11
// --------------------------------------------------
#define DHTPIN  4
#define DHTTYPE DHT11
DHT dht(DHTPIN, DHTTYPE);

// --------------------------------------------------
// AES Key (AES-128, 16 bytes)
// --------------------------------------------------
uint8_t AES_KEY[16];

// --------------------------------------------------
// MQTT / OTA globals
// --------------------------------------------------
String mqttServer = "";
String mqttUser   = "";
String mqttPass   = "";
int    mqttPort   = 8883;

volatile bool otaRequested  = false;
String        pendingOTAUrl = "";

// --------------------------------------------------
// CA Certificate (ISRG Root X1 — Let's Encrypt)
// --------------------------------------------------
const char* ca_cert = R"EOF(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
)EOF";

WiFiClientSecure secureClient;
PubSubClient     client(secureClient);
Preferences      prefs;

// --------------------------------------------------
// Utility: bytes <-> hex
// --------------------------------------------------
String bytesToHex(const uint8_t *data, size_t len)
{
    String hex = "";
    for (size_t i = 0; i < len; i++)
    {
        char buf[3];
        sprintf(buf, "%02X", data[i]);
        hex += buf;
    }
    return hex;
}

void hexToBytes(const String &hex, uint8_t *out, size_t outLen)
{
    for (size_t i = 0; i < outLen; i++)
    {
        sscanf(
            hex.substring(i * 2, i * 2 + 2).c_str(),
            "%2hhx",
            &out[i]
        );
    }
}

// --------------------------------------------------
// AES Key initialisation (persisted in NVS)
// --------------------------------------------------
void initializeAESKey()
{
    prefs.begin("security", false);
    String storedKey = prefs.getString("aes_key", "");

    if (storedKey.length() != 32)
    {
        uint8_t newKey[16];
        for (int i = 0; i < 16; i++)
            newKey[i] = esp_random() & 0xFF;

        storedKey = bytesToHex(newKey, 16);
        prefs.putString("aes_key", storedKey);
        Serial.println("New AES key generated and saved");
    }
    else
    {
        Serial.println("AES key loaded from NVS");
    }

    hexToBytes(storedKey, AES_KEY, 16);
    prefs.end();
}

// --------------------------------------------------
// HMAC-SHA256
// --------------------------------------------------
String createHMAC(String payload)
{
    unsigned char hmac[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(
        &ctx,
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        1
    );
    mbedtls_md_hmac_starts(&ctx, AES_KEY, 16);
    mbedtls_md_hmac_update(
        &ctx,
        (unsigned char*)payload.c_str(),
        payload.length()
    );
    mbedtls_md_hmac_finish(&ctx, hmac);
    mbedtls_md_free(&ctx);

    String result = "";
    for (int i = 0; i < 32; i++)
    {
        char tmp[3];
        sprintf(tmp, "%02x", hmac[i]);
        result += tmp;
    }
    return result;
}

// --------------------------------------------------
// AES-128-CBC encrypt → ivHex:base64(ciphertext)
// --------------------------------------------------
void generateRandomIV(uint8_t *iv)
{
    for (int i = 0; i < 16; i++)
        iv[i] = esp_random() & 0xFF;
}

String encryptAES(String plainText)
{
    uint8_t randomIV[16];
    generateRandomIV(randomIV);

    int inputLen  = plainText.length();
    int paddedLen = ((inputLen / 16) + 1) * 16;

    uint8_t input[paddedLen];
    memset(input, 0, paddedLen);
    memcpy(input, plainText.c_str(), inputLen);

    uint8_t pad = paddedLen - inputLen;
    for (int i = inputLen; i < paddedLen; i++)
        input[i] = pad;

    uint8_t output[paddedLen];

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    uint8_t iv[16];
    memcpy(iv, randomIV, 16);

    mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);
    mbedtls_aes_crypt_cbc(
        &aes,
        MBEDTLS_AES_ENCRYPT,
        paddedLen,
        iv,
        input,
        output
    );
    mbedtls_aes_free(&aes);

    size_t        outLen = 0;
    unsigned char base64Buf[512];
    mbedtls_base64_encode(
        base64Buf, sizeof(base64Buf),
        &outLen,
        output, paddedLen
    );
    base64Buf[outLen] = '\0';

    String ivHex = "";
    for (int i = 0; i < 16; i++)
    {
        char buf[3];
        sprintf(buf, "%02X", randomIV[i]);
        ivHex += buf;
    }

    return ivHex + ":" + String((char*)base64Buf);
}

// --------------------------------------------------
// OTA over HTTP
// --------------------------------------------------
void doOTA(String url)
{
    Serial.println("========== OTA UPDATE ==========");
    Serial.print("Downloading: ");
    Serial.println(url);

    WiFiClientSecure otaClient;
    otaClient.setInsecure();                         // relax TLS for OTA host
    httpUpdate.rebootOnUpdate(true);
    httpUpdate.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);

    t_httpUpdate_return ret = httpUpdate.update(otaClient, url);

    switch (ret)
    {
        case HTTP_UPDATE_FAILED:
            Serial.printf(
                "Update failed (%d): %s\n",
                httpUpdate.getLastError(),
                httpUpdate.getLastErrorString().c_str()
            );
            break;
        case HTTP_UPDATE_NO_UPDATES:
            Serial.println("No update available");
            break;
        case HTTP_UPDATE_OK:
            Serial.println("Update successful");
            break;
    }
}

// --------------------------------------------------
// MQTT callback
// --------------------------------------------------
void callback(char* topic, byte* payload, unsigned int length)
{
    String msg = "";
    for (unsigned int i = 0; i < length; i++)
        msg += (char)payload[i];

    Serial.print("Topic: ");   Serial.println(topic);
    Serial.print("Payload: "); Serial.println(msg);

    if (String(topic) == "home/esp32/update")
    {
        DynamicJsonDocument doc(512);
        DeserializationError err = deserializeJson(doc, msg);
        if (err)
        {
            Serial.println("Invalid OTA JSON");
            return;
        }

        String newVersion = doc["version"].as<String>();
        String otaUrl     = doc["url"].as<String>();

        Serial.print("Current Version:   "); Serial.println(FW_VERSION);
        Serial.print("Available Version: "); Serial.println(newVersion);

        if (newVersion == FW_VERSION)
        {
            Serial.println("Already up to date");
            return;
        }

        Serial.println("New firmware detected — scheduling OTA");
        pendingOTAUrl = otaUrl;
        otaRequested  = true;
    }
}

// --------------------------------------------------
// setupConfigPortal
// FIX: use autoConnect so saved credentials are used
//      on boot without manual WiFi.begin() conflict.
//      setSaveParamsCallback persists MQTT values when
//      the user submits the portal form.
// --------------------------------------------------
void setupConfigPortal()
{
    // Load previously saved MQTT config from NVS
    prefs.begin("config", true);
    String savedServer = prefs.getString("mqtt_server", "");
    String savedUser   = prefs.getString("mqtt_user",   "");
    String savedPass   = prefs.getString("mqtt_pass",   "");
    prefs.end();

    // Build WiFiManager custom parameters
    WiFiManagerParameter custom_mqtt_server(
        "server", "MQTT Server",   savedServer.c_str(), 100);
    WiFiManagerParameter custom_mqtt_user(
        "user",   "MQTT Username", savedUser.c_str(),   50);
    WiFiManagerParameter custom_mqtt_pass(
        "pass",   "MQTT Password", savedPass.c_str(),   50);

    wm.addParameter(&custom_mqtt_server);
    wm.addParameter(&custom_mqtt_user);
    wm.addParameter(&custom_mqtt_pass);

    // FIX: persist MQTT params the moment the user hits Save in the portal
    wm.setSaveParamsCallback([&]() {
        String newServer = String(custom_mqtt_server.getValue());
        String newUser   = String(custom_mqtt_user.getValue());
        String newPass   = String(custom_mqtt_pass.getValue());

        prefs.begin("config", false);
        prefs.putString("mqtt_server", newServer);
        prefs.putString("mqtt_user",   newUser);
        prefs.putString("mqtt_pass",   newPass);
        prefs.end();

        mqttServer = newServer;
        mqttUser   = newUser;
        mqttPass   = newPass;

        Serial.println("MQTT config saved from portal");
    });

    // Optional: close the portal after 3 minutes if no one connects
    wm.setConfigPortalTimeout(180);

    // FIX: autoConnect does everything:
    //   • Saved credentials present → connects automatically (no portal)
    //   • No saved credentials      → starts blocking portal
    // This replaces the broken manual loadSavedWifiCredentials + WiFi.begin()
    Serial.println("Starting WiFiManager autoConnect...");
    bool connected = wm.autoConnect("ESP32_Config", "admin123");

    if (!connected)
    {
        // Portal timed out or connection failed — restart and try again
        Serial.println("WiFiManager failed to connect. Restarting...");
        ESP.restart();
    }

    Serial.println("WiFi connected via WiFiManager");

    // Read MQTT values — either freshly entered or still from NVS
    mqttServer = String(custom_mqtt_server.getValue());
    mqttUser   = String(custom_mqtt_user.getValue());
    mqttPass   = String(custom_mqtt_pass.getValue());

    // If NVS had values but portal wasn't shown, getValue() returns the
    // default string we passed in (savedServer/User/Pass), which is correct.
    Serial.print("MQTT Server: "); Serial.println(mqttServer);
}

// --------------------------------------------------
// RTOS Task: MQTT keep-alive + loop
// --------------------------------------------------
void mqttTask(void *pvParameters)
{
    while (true)
    {
        if (xSemaphoreTake(mqttMutex, pdMS_TO_TICKS(100)))
        {
            if (!client.connected())
            {
                if (millis() - lastReconnectAttempt >= 5000)
                {
                    lastReconnectAttempt = millis();

                    Serial.print("Connecting MQTT... ");

                    String clientId =
                        "ESP32_" +
                        String((uint32_t)ESP.getEfuseMac(), HEX);

                    if (client.connect(
                            clientId.c_str(),
                            mqttUser.c_str(),
                            mqttPass.c_str()))
                    {
                        Serial.println("connected");
                        client.subscribe("home/esp32/update");
                        Serial.println("Subscribed to OTA topic");
                    }
                    else
                    {
                        Serial.print("failed rc=");
                        Serial.println(client.state());
                    }
                }
            }

            client.loop();
            xSemaphoreGive(mqttMutex);
        }

        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

// --------------------------------------------------
// RTOS Task: OTA (ArduinoOTA + HTTP OTA)
// --------------------------------------------------
void otaTask(void *pvParameters)
{
    while (true)
    {
        ArduinoOTA.handle();

        if (otaRequested)
        {
            otaRequested = false;
            Serial.println("Starting OTA...");
            Serial.printf(
                "OTA stack free before update: %u\n",
                uxTaskGetStackHighWaterMark(NULL)
            );
            doOTA(pendingOTAUrl);
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// --------------------------------------------------
// RTOS Task: DHT11 sensor → encrypt → publish
// --------------------------------------------------
void sensorTask(void *pvParameters)
{
    while (true)
    {
        float temp = dht.readTemperature();
        float hum  = dht.readHumidity();

        if (!isnan(temp) && !isnan(hum))
        {
            DynamicJsonDocument doc(512);
            doc["temp"]      = temp;
            doc["hum"]       = hum;
            doc["device"]    = "ESP32_01";
            doc["timestamp"] = time(nullptr);
            doc["nonce"]     = String(esp_random());

            String payload;
            serializeJson(doc, payload);

            // Add HMAC over the plain payload
            String hmac    = createHMAC(payload);
            doc["hmac"]    = hmac;
            serializeJson(doc, payload);

            String encrypted = encryptAES(payload);

            if (xSemaphoreTake(mqttMutex, pdMS_TO_TICKS(1000)))
            {
                if (client.connected())
                {
                    Serial.print("Encrypted Length = ");
                    Serial.println(encrypted.length());

                    bool result = client.publish(
                        "home/esp32/encrypted",
                        encrypted.c_str()
                    );

                    Serial.print("Publish result = ");
                    Serial.println(result);
                }
                xSemaphoreGive(mqttMutex);
            }

            Serial.println("Plain:");
            Serial.println(payload);
            Serial.println("Encrypted:");
            Serial.println(encrypted);
        }
        else
        {
            Serial.println("DHT11 read failed");
        }

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

// --------------------------------------------------
// RTOS Task: WiFi watchdog & reconnect
// FIX: no longer relies on loadSavedWifiCredentials().
//      Uses WiFi.begin() with credentials from
//      WiFiManager's internal storage (flash), which
//      are always available after the first portal run.
// --------------------------------------------------
void wifiTask(void *pvParameters)
{
    while (true)
    {
        if (WiFi.status() == WL_CONNECTED)
        {
            // Connection healthy — reset failure counter
            if (portalRunning)
            {
                Serial.println("WiFi restored. Closing portal.");
                wm.stopConfigPortal();
                portalRunning = false;
            }
            wifiFailureCount = 0;
        }
        else
        {
            Serial.println("WiFi lost. Attempting reconnect...");

            // Let the WiFi stack settle before reconnecting
            WiFi.disconnect(false, false);
            vTaskDelay(pdMS_TO_TICKS(1000));

            // FIX: use wm.autoConnect() style reconnect so WiFiManager's
            // stored credentials (saved to flash by the portal) are used.
            // WiFi.reconnect() achieves the same without re-running setup.
            WiFi.reconnect();

            int retries = 0;
            while (WiFi.status() != WL_CONNECTED && retries < 20)
            {
                if (portalRunning)
                    wm.process();

                Serial.print(".");
                vTaskDelay(pdMS_TO_TICKS(500));
                retries++;
            }
            Serial.println();

            if (WiFi.status() == WL_CONNECTED)
            {
                Serial.println("WiFi reconnected");
                Serial.println(WiFi.localIP());
                wifiFailureCount = 0;
            }
            else
            {
                wifiFailureCount++;
                Serial.print("Reconnect failed. Count=");
                Serial.println(wifiFailureCount);

                // After 6 consecutive failures, open the config portal
                if (wifiFailureCount >= 6 && !portalRunning)
                {
                    Serial.println("Starting Config Portal...");
                    wm.setConfigPortalBlocking(false);
                    wm.startConfigPortal("ESP32_Config", "admin123");
                    portalRunning = true;
                }
            }
        }

        // If portal is running, keep processing it between checks
        if (portalRunning)
        {
            for (int i = 0; i < 100; i++)   // ~10 s of portal processing
            {
                wm.process();
                vTaskDelay(pdMS_TO_TICKS(100));
            }
        }
        else
        {
            vTaskDelay(pdMS_TO_TICKS(10000));
        }
    }
}

// --------------------------------------------------
// Setup
// --------------------------------------------------
void setup()
{
    Serial.begin(115200);
    delay(3000);

    // AES key must be ready before anything uses crypto
    Serial.println("Initialising AES key...");
    initializeAESKey();

    Serial.print("AES Key: ");
    for (int i = 0; i < 16; i++)
        Serial.printf("%02X", AES_KEY[i]);
    Serial.println();

    dht.begin();

    // FIX: setupConfigPortal() now blocks here until WiFi is connected
    // (either via saved credentials automatically, or via portal entry).
    // No separate WiFi wait loop needed below.
    setupConfigPortal();

    Serial.print("Firmware Version: ");
    Serial.println(FW_VERSION);

    // ArduinoOTA (LAN OTA)
    ArduinoOTA.setHostname("ESP32-Sensor");
    ArduinoOTA.onStart([]() { Serial.println("OTA Start"); });
    ArduinoOTA.onEnd([]()   { Serial.println("\nOTA End"); });
    ArduinoOTA.onError([](ota_error_t error) {
        Serial.printf("OTA Error[%u]\n", error);
    });
    ArduinoOTA.begin();

    Serial.println("OTA Ready");
    Serial.print("IP: ");
    Serial.println(WiFi.localIP());

    // Sync time (IST = UTC+5:30 = 19800 s offset)
    configTime(19800, 0, "pool.ntp.org", "time.nist.gov");
    struct tm timeinfo;
    while (!getLocalTime(&timeinfo))
    {
        Serial.println("Waiting for NTP...");
        delay(1000);
    }
    Serial.println("Time synced");

    // TLS + MQTT
    secureClient.setCACert(ca_cert);
    client.setServer(mqttServer.c_str(), mqttPort);
    client.setBufferSize(1024);
    client.setCallback(callback);

    // Mutex
    mqttMutex = xSemaphoreCreateMutex();
    if (mqttMutex == NULL)
    {
        Serial.println("Mutex creation failed — restarting");
        ESP.restart();
    }

    // Launch RTOS tasks
    xTaskCreatePinnedToCore(mqttTask,   "MQTT",   16384, NULL, 3, &mqttTaskHandle,   1);
    xTaskCreatePinnedToCore(sensorTask, "Sensor",  6144, NULL, 2, &sensorTaskHandle,  1);
    xTaskCreatePinnedToCore(otaTask,    "OTA",    16384, NULL, 1, &otaTaskHandle,     0);
    xTaskCreatePinnedToCore(wifiTask,   "WiFi",    4096, NULL, 2, &wifiTaskHandle,    0);

    Serial.println("All RTOS tasks started");
}

// --------------------------------------------------
// Loop — all real work is in RTOS tasks
// --------------------------------------------------
void loop()
{
    vTaskDelay(pdMS_TO_TICKS(1000));
}
