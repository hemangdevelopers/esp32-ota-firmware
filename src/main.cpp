#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <ArduinoOTA.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <ArduinoJson.h>

#include "mbedtls/aes.h"
#include "mbedtls/base64.h"

#define FW_VERSION "5.0"

// ---------------- WiFi ----------------
const char* ssid = "Hemang's S23 FE";
const char* password = "hemang123";

// ---------------- MQTT ----------------
const char* mqtt_server = "1f29758fe6fe4b919f1d6b308790f9d8.s1.eu.hivemq.cloud";
const int mqtt_port = 8883;

// ---------------- MQTT Credentials ----------------
const char* mqtt_user = "esp32";
const char* mqtt_pass = "Esp@12345";

// ---------------- DHT11 ----------------
#define DHTPIN 4
#define DHTTYPE DHT11

DHT dht(DHTPIN, DHTTYPE);

// ---------------- AES ----------------
// 16-byte key (AES-128)
const unsigned char AES_KEY[16] = {
  '1','2','3','4',
  '5','6','7','8',
  '9','0','1','2',
  '3','4','5','6'
};

void generateRandomIV(uint8_t *iv)
{
  for(int i = 0; i < 16; i++)
  {
    iv[i] = esp_random() & 0xFF;
  }
}

// ---------------- CA Certificate ----------------
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
PubSubClient client(secureClient);
HTTPClient https;

// --------------------------------------------------
// AES-CBC + Base64
// --------------------------------------------------
String encryptAES(String plainText)
{
  uint8_t randomIV[16];
  generateRandomIV(randomIV);

  int inputLen = plainText.length();
  int paddedLen = ((inputLen / 16) + 1) * 16;

  uint8_t input[paddedLen];
  memset(input, 0, paddedLen);
  memcpy(input, plainText.c_str(), inputLen);

  uint8_t pad = paddedLen - inputLen;

  for(int i = inputLen; i < paddedLen; i++)
  {
    input[i] = pad;
  }

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

  size_t outLen = 0;
  unsigned char base64Buf[512];

  mbedtls_base64_encode(
      base64Buf,
      sizeof(base64Buf),
      &outLen,
      output,
      paddedLen
  );

  base64Buf[outLen] = '\0';

  String cipherText = String((char*)base64Buf);

  String ivHex = "";

  for(int i = 0; i < 16; i++)
  {
    char buf[3];
    sprintf(buf, "%02X", randomIV[i]);
    ivHex += buf;
  }

  return ivHex + ":" + cipherText;
}

// --------------------------------------------------
// MQTT Reconnect
// --------------------------------------------------
void reconnect()
{
  if (client.connected()) return;

  Serial.print("Connecting MQTT...");

  String clientId =
    "ESP32_" +
    String((uint32_t)ESP.getEfuseMac(), HEX);

  if (client.connect(
        clientId.c_str(),
        mqtt_user,
        mqtt_pass))
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

void callback(char* topic, byte* payload, unsigned int length);
void doOTA(String url);
void doOTA(String url)
{
  Serial.println("========== OTA UPDATE ==========");
  Serial.print("Downloading: ");
  Serial.println(url);

  WiFiClientSecure otaClient;
  otaClient.setInsecure();

  httpUpdate.rebootOnUpdate(true);

  httpUpdate.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);

  t_httpUpdate_return ret =
      httpUpdate.update(otaClient, url);

  switch(ret)
  {
    case HTTP_UPDATE_FAILED:
      Serial.printf("Update failed (%d): %s\n",
        httpUpdate.getLastError(),
        httpUpdate.getLastErrorString().c_str());
      break;

    case HTTP_UPDATE_NO_UPDATES:
      Serial.println("No update available");
      break;

    case HTTP_UPDATE_OK:
      Serial.println("Update successful");
      break;
  }
}
void callback(char* topic, byte* payload, unsigned int length)
{
  String msg = "";

  for(unsigned int i=0;i<length;i++)
  {
    msg += (char)payload[i];
  }

  Serial.print("Topic: ");
  Serial.println(topic);

  Serial.print("Payload: ");
  Serial.println(msg);

  if(String(topic) == "home/esp32/update")
  {
    doOTA(msg);
  }
}

// --------------------------------------------------
// Setup
// --------------------------------------------------
void setup()
{
  Serial.begin(115200);

  dht.begin();

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi connected");

  Serial.print("Firmware Version: ");
  Serial.println(FW_VERSION);
   
  ArduinoOTA.setHostname("ESP32-Sensor");

  ArduinoOTA.onStart([]() {
  Serial.println("OTA Start");
  });

  ArduinoOTA.onEnd([]() {
  Serial.println("\nOTA End");
  });

  ArduinoOTA.onError([](ota_error_t error) {
  Serial.printf("OTA Error[%u]\n", error);
  });

  ArduinoOTA.begin();

  Serial.println("OTA Ready");
  Serial.print("IP: ");
  Serial.println(WiFi.localIP());

  // TLS requires correct time
  configTime(
    19800,
    0,
    "pool.ntp.org",
    "time.nist.gov"
  );

  struct tm timeinfo;

  while (!getLocalTime(&timeinfo))
  {
    Serial.println("Waiting for NTP...");
    delay(1000);
  }

  Serial.println("Time synced");

  secureClient.setCACert(ca_cert);
  
  client.setServer(
    mqtt_server,
    mqtt_port
  );
  client.setCallback(callback);
}

// --------------------------------------------------
// Loop
// --------------------------------------------------
void loop()
{
  ArduinoOTA.handle();

  if (!client.connected())
  {
    reconnect();
  }

  client.loop();

  float temp = dht.readTemperature();
  float hum  = dht.readHumidity();

  if (isnan(temp) || isnan(hum))
  {
    Serial.println("DHT11 read failed");
    delay(5000);
    return;
  }

  String json =
    "{\"temp\":" +
    String(temp, 1) +
    ",\"hum\":" +
    String(hum, 1) +
    "}";

  String encrypted =
    encryptAES(json);

  client.publish(
    "home/esp32/encrypted",
    encrypted.c_str()
  );

  Serial.println("Plain:");
  Serial.println(json);

  Serial.println("Encrypted:");
  Serial.println(encrypted);

  unsigned long start = millis();

  while (millis() - start < 5000)
  {
    ArduinoOTA.handle();
    client.loop();
    delay(50);
  }
}

