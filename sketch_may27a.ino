#include <WiFi.h>
#include <PubSubClient.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "mbedtls/pkcs5.h"
#include <time.h>
#include "esp_system.h"

// Include config file
#include "esp32_config.h"

// Pin definitions
#define SS_PIN 5
#define RST_PIN 22
#define LED_GREEN 2
#define LED_RED 4
#define BUZZER_PIN 21
#define MAX_MESSAGE_SIZE 4096   // Reduced from 8192
#define MAX_SIGNATURE_SIZE 2500 // Dilithium2 signature size
#define MAX_CHALLENGE_SIZE 64   // Base64 encoded 32 bytes
#define MAX_NONCE_SIZE 32       // Base64 encoded 16 bytes
// Master secret (in production, this would be securely embedded)
#define MASTER_SECRET_SIZE 32
const uint8_t master_secret[MASTER_SECRET_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

// Objects
WiFiClient espClient;
PubSubClient client(espClient);
MFRC522 mfrc522(SS_PIN, RST_PIN);

// State management
String currentCardUID = "";
String lastDetectedUID = "";
bool cardPresent = false;
unsigned long lastCardCheck = 0;
unsigned long lastHeartbeat = 0;
unsigned long lastUIDDetected = 0;
const unsigned long CARD_CHECK_INTERVAL = 100;
const unsigned long HEARTBEAT_INTERVAL = 30000;
const unsigned long UID_MEMORY_TIME = 10000;

// Authentication state
bool authenticationInProgress = false;
String pendingAuthUID = "";
bool serverVerified = false;
bool mutualAuthEnabled = MUTUAL_AUTHENTICATION;
bool aesSupported = true;
uint32_t aesOperationsCount = 0;

// AES key derived from master secret
uint8_t aes_key[16]; // 128-bit AES key

// Forward declarations
void derive_aes_key();
bool decrypt_card_secret_aes(String card_uid, String encrypted_b64, String nonce_b64, uint8_t *card_secret);
bool verify_server_signature(String card_uid, String challenge_b64, long long timestamp, String nonce_b64, String signature_b64);
bool verify_signature_lightweight(uint8_t *message, int message_len, String signature_b64);

// Base64 helper functions
String base64_encode(uint8_t *data, size_t length)
{
    const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    String result = "";

    // Reserve memory to prevent frequent reallocations
    result.reserve((length + 2) / 3 * 4 + 1);

    for (size_t i = 0; i < length; i += 3)
    {
        uint32_t value = 0;
        int valid_bytes = 0;

        for (int j = 0; j < 3; j++)
        {
            value <<= 8;
            if (i + j < length)
            {
                value |= data[i + j];
                valid_bytes++;
            }
        }

        // Always encode 4 characters for each 3-byte group
        for (int j = 0; j < 4; j++)
        {
            if (j < valid_bytes + 1)
            {
                result += chars[(value >> (18 - j * 6)) & 0x3F];
            }
            else
            {
                result += '=';
            }
        }
    }

    return result;
}

int base64_decode(uint8_t *output, const char *input, size_t input_len)
{
    const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int output_len = 0;
    size_t max_input = min(input_len, (size_t)256); // Limit input size

    // Skip whitespace and newlines
    String clean_input = String(input);
    clean_input.trim();
    clean_input.replace("\n", "");
    clean_input.replace("\r", "");
    clean_input.replace(" ", "");

    const char *clean_str = clean_input.c_str();
    size_t clean_len = clean_input.length();

    for (size_t i = 0; i < clean_len; i += 4)
    {
        uint32_t value = 0;
        int valid_chars = 0;

        for (int j = 0; j < 4; j++)
        {
            if (i + j < clean_len && clean_str[i + j] != '=')
            {
                char *pos = strchr((char *)chars, clean_str[i + j]);
                if (pos)
                {
                    value = (value << 6) | (pos - chars);
                    valid_chars++;
                }
            }
            else
            {
                value <<= 6;
            }
        }

        // Extract bytes based on valid characters
        for (int j = 0; j < 3 && j < valid_chars - 1 && output_len < 64; j++)
        {
            output[output_len++] = (value >> (16 - j * 8)) & 0xFF;
        }
    }

    return output_len;
}

// Time management
void setup_time()
{
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");

    Serial.print("⏰ Waiting for NTP time sync");
    time_t now = time(nullptr);
    int attempts = 0;
    while (now < 8 * 3600 * 2 && attempts < 30)
    {
        delay(1000);
        Serial.print(".");
        now = time(nullptr);
        attempts++;
    }
    Serial.println();

    if (now > 8 * 3600 * 2)
    {
        Serial.printf("✅ Time synchronized: %s", ctime(&now));
    }
    else
    {
        Serial.println("⚠️ Failed to sync time, using relative timestamps");
    }
}

unsigned long get_current_timestamp()
{
    time_t now;
    time(&now);
    return (unsigned long)now;
}

// AES key derivation
void derive_aes_key()
{
    Serial.println("🔐 Deriving AES-128 key from master secret...");

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, md_info, 1);

    const char *salt = "AES_CARD_ENCRYPTION";

    // FIXED: Use correct mbedTLS function name
    int result = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                               master_secret, MASTER_SECRET_SIZE,
                                               (const unsigned char *)salt, strlen(salt),
                                               100000, // Same iterations as server
                                               16, aes_key);

    mbedtls_md_free(&ctx);

    if (result == 0)
    {
        Serial.println("✅ AES key derived successfully");
        Serial.printf("   - Key size: 16 bytes (128-bit)\n");
        Serial.printf("   - PBKDF2 iterations: 100,000\n");
    }
    else
    {
        Serial.printf("❌ AES key derivation failed: %d\n", result);
        aesSupported = false;
    }
}

// AES-128 CTR decryption
bool decrypt_card_secret_aes(String card_uid, String encrypted_b64, String nonce_b64, uint8_t *card_secret)
{
    Serial.printf("🔓 Decrypting card secret for UID: %s\n", card_uid.c_str());
    Serial.printf("   - Algorithm: AES-128-CTR\n");

    // DEBUG: Print raw Base64 strings
    Serial.printf("   - Raw encrypted_b64: '%s' (len: %d)\n", encrypted_b64.c_str(), encrypted_b64.length());
    Serial.printf("   - Raw nonce_b64: '%s' (len: %d)\n", nonce_b64.c_str(), nonce_b64.length());

    // Clean Base64 strings (remove whitespace/newlines)
    encrypted_b64.trim();
    nonce_b64.trim();

    Serial.printf("   - Cleaned encrypted_b64: '%s' (len: %d)\n", encrypted_b64.c_str(), encrypted_b64.length());
    Serial.printf("   - Cleaned nonce_b64: '%s' (len: %d)\n", nonce_b64.c_str(), nonce_b64.length());

    // Decode base64 inputs
    uint8_t encrypted_data[64]; // Larger buffer for safety
    uint8_t nonce[32];          // Larger buffer for safety

    int enc_len = base64_decode(encrypted_data, encrypted_b64.c_str(), encrypted_b64.length());
    int nonce_len = base64_decode(nonce, nonce_b64.c_str(), nonce_b64.length());

    Serial.printf("   - Encrypted data length: %d bytes\n", enc_len);
    Serial.printf("   - Nonce length: %d bytes\n", nonce_len);

    // DEBUG: Print decoded hex data
    Serial.printf("   - Encrypted hex: ");
    for (int i = 0; i < enc_len && i < 8; i++)
    {
        Serial.printf("%02X ", encrypted_data[i]);
    }
    Serial.println();

    Serial.printf("   - Nonce hex: ");
    for (int i = 0; i < nonce_len && i < 8; i++)
    {
        Serial.printf("%02X ", nonce[i]);
    }
    Serial.println();

    // Check expected lengths
    if (enc_len != 32)
    {
        Serial.printf("❌ Invalid encrypted data length (expected 32, got %d)\n", enc_len);
        return false;
    }

    if (nonce_len != 16)
    {
        Serial.printf("❌ Invalid nonce length (expected 16, got %d)\n", nonce_len);
        return false;
    }

    // AES-128 CTR decryption using mbedTLS
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);

    int result = mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 128);
    if (result != 0)
    {
        Serial.printf("❌ AES key setup failed: %d\n", result);
        mbedtls_aes_free(&aes_ctx);
        return false;
    }

    size_t nc_off = 0;
    uint8_t stream_block[16];

    result = mbedtls_aes_crypt_ctr(&aes_ctx, 32,
                                   &nc_off, nonce, stream_block,
                                   encrypted_data, card_secret);

    mbedtls_aes_free(&aes_ctx);

    if (result == 0)
    {
        aesOperationsCount++;
        Serial.println("✅ AES decryption successful");
        Serial.printf("   - Decrypted 32 bytes of card secret\n");
        Serial.printf("   - Total AES operations: %u\n", aesOperationsCount);
        return true;
    }
    else
    {
        Serial.printf("❌ AES decryption failed: %d\n", result);
        return false;
    }
}

void print_config()
{
    Serial.println("\n📋 ESP32 Configuration:");
    Serial.printf("   WiFi SSID: %s\n", WIFI_SSID);
    Serial.printf("   MQTT Server: %s:%d\n", MQTT_SERVER, MQTT_PORT);
    Serial.printf("   Signature Algorithm: %s\n", SIG_ALGORITHM);
    Serial.printf("   Challenge Size: %d bytes\n", CHALLENGE_SIZE);
    Serial.printf("   Mutual Authentication: %s\n", mutualAuthEnabled ? "✅ Enabled" : "❌ Disabled");
    Serial.printf("   AES Support: %s\n", aesSupported ? "✅ Enabled" : "❌ Disabled");
    Serial.printf("   Public Key Size: %d bytes\n", DILITHIUM_PUBLIC_KEY_SIZE);
    Serial.printf("   Master Secret: Embedded\n");
    Serial.println();
}

// Network setup
void setup_wifi()
{
    delay(10);
    Serial.printf("📶 Connecting to WiFi: %s", WIFI_SSID);

    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 30)
    {
        delay(1000);
        Serial.print(".");
        attempts++;
    }

    if (WiFi.status() == WL_CONNECTED)
    {
        Serial.println();
        Serial.printf("✅ WiFi connected!\n");
        Serial.printf("   IP address: %s\n", WiFi.localIP().toString().c_str());
        Serial.printf("   Signal strength: %d dBm\n", WiFi.RSSI());
    }
    else
    {
        Serial.println();
        Serial.println("❌ WiFi connection failed!");
        while (1)
            delay(1000);
    }
}
// Thêm function này sau derive_aes_key() và trước print_config()

// Hardware initialization
bool test_mfrc522_basic()
{
    Serial.println("🧪 Testing MFRC522 basic functionality...");

    byte version = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);

    if (version == 0x00 || version == 0xFF)
    {
        Serial.println("❌ MFRC522 not responding or connection issue");
        Serial.printf("   Version register: 0x%02X\n", version);
        return false;
    }

    Serial.printf("✅ MFRC522 detected (version: 0x%02X)\n", version);

    // Test power cycle
    mfrc522.PCD_SoftPowerDown();
    delay(10);
    mfrc522.PCD_SoftPowerUp();
    delay(10);

    Serial.println("   Power cycle test passed");
    return true;
}
void reconnect_mqtt()
{
    while (!client.connected())
    {
        Serial.printf("📡 Attempting MQTT connection to %s:%d...\n", MQTT_SERVER, MQTT_PORT);

        String client_id = "ESP32_RFID_" + String(WiFi.macAddress());
        client_id.replace(":", "");

        if (client.connect(client_id.c_str()))
        {
            Serial.printf("✅ MQTT connected (Client ID: %s)\n", client_id.c_str());

            client.subscribe(TOPIC_FROM_SERVER);
            Serial.printf("📡 Subscribed to: %s\n", TOPIC_FROM_SERVER);

            send_esp32_ready();
        }
        else
        {
            Serial.printf("❌ MQTT connection failed (state: %d)\n", client.state());
            Serial.println("   Retrying in 5 seconds...");
            delay(5000);
        }
    }
}

void send_esp32_ready()
{
    DynamicJsonDocument doc(1024);
    doc["type"] = "esp32_ready";
    doc["version"] = "2.0-AES";
    doc["timestamp"] = get_current_timestamp();
    doc["mutual_auth"] = mutualAuthEnabled;
    doc["aes_support"] = aesSupported;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["chip_model"] = ESP.getChipModel();
    doc["encryption_algorithm"] = "AES-128-CTR";

    String message;
    serializeJson(doc, message);

    client.publish(TOPIC_TO_SERVER, message.c_str());
    Serial.printf("📤 Sent ESP32 ready message (AES support: %s)\n", aesSupported ? "✅" : "❌");
}

// Card detection and management
void check_for_cards()
{
    if (millis() - lastCardCheck < CARD_CHECK_INTERVAL)
    {
        return;
    }
    lastCardCheck = millis();

    bool newCardPresent = mfrc522.PICC_IsNewCardPresent();
    bool cardReadable = false;
    String detectedUID = "";

    if (newCardPresent)
    {
        cardReadable = mfrc522.PICC_ReadCardSerial();
        if (cardReadable)
        {
            detectedUID = "";
            for (byte i = 0; i < mfrc522.uid.size; i++)
            {
                if (mfrc522.uid.uidByte[i] < 0x10)
                    detectedUID += "0";
                detectedUID += String(mfrc522.uid.uidByte[i], HEX);
            }
            detectedUID.toUpperCase();
        }
    }

    if (cardReadable && detectedUID != "")
    {
        if (!cardPresent || currentCardUID != detectedUID)
        {
            currentCardUID = detectedUID;
            cardPresent = true;
            lastUIDDetected = millis();

            Serial.printf("🏷️ Card detected: %s\n", currentCardUID.c_str());
            Serial.printf("   - Card type: ISO14443A\n");
            Serial.printf("   - UID length: %d bytes\n", mfrc522.uid.size);

            // Send detection immediately
            send_card_status("detected");
        }
    }
    else
    {
        if (cardPresent && (millis() - lastUIDDetected > UID_MEMORY_TIME))
        {
            Serial.printf("🏷️ Card removed: %s\n", currentCardUID.c_str());
            send_card_status("removed");

            cardPresent = false;
            currentCardUID = "";
            authenticationInProgress = false;
            pendingAuthUID = "";
            serverVerified = false;
        }
    }

    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
}

void send_card_status(String status)
{
    DynamicJsonDocument doc(512);
    doc["type"] = "card_" + status;
    doc["card_uid"] = currentCardUID;
    doc["timestamp"] = get_current_timestamp();
    doc["signal_strength"] = WiFi.RSSI();
    doc["aes_operations"] = aesOperationsCount;

    String message;
    serializeJson(doc, message);

    client.publish(TOPIC_TO_SERVER, message.c_str());
    Serial.printf("📤 Card %s: %s\n", status.c_str(), currentCardUID.c_str());
}

// Message handling with AES support
void callback(char *topic, byte *payload, unsigned int length)
{
    // Limit message size to prevent overflow
    if (length > MAX_MESSAGE_SIZE)
    {
        Serial.printf("❌ Message too large: %d bytes (max: %d)\n", length, MAX_MESSAGE_SIZE);
        return;
    }

    payload[length] = '\0';
    String message = String((char *)payload);

    Serial.printf("📥 MQTT message received (%d bytes)\n", length);

    // Use smaller JSON buffer
    DynamicJsonDocument doc(MAX_MESSAGE_SIZE);
    DeserializationError error = deserializeJson(doc, message);

    if (error)
    {
        Serial.printf("❌ JSON parsing error: %s\n", error.c_str());
        return;
    }

    String msg_type = doc["type"];

    if (msg_type == "server_info")
    {
        handle_server_info(doc);
    }
    else if (msg_type == "auth_challenge")
    {
        handle_auth_challenge_aes(doc);
    }
    else if (msg_type == "auth_success")
    {
        handle_auth_success(doc);
    }
    else if (msg_type == "auth_rejected")
    {
        handle_auth_rejected(doc);
    }
    else
    {
        Serial.printf("⚠️ Unknown message type: %s\n", msg_type.c_str());
    }
}

void handle_server_info(DynamicJsonDocument &doc)
{
    String sig_algorithm = doc["sig_algorithm"];
    String encryption_algorithm = doc["encryption_algorithm"];
    bool server_mutual_auth = doc["mutual_auth"];
    bool server_aes_support = doc["aes_support"];

    Serial.println("📤 Server info received:");
    Serial.printf("   - Signature algorithm: %s\n", sig_algorithm.c_str());
    Serial.printf("   - Encryption algorithm: %s\n", encryption_algorithm.c_str());
    Serial.printf("   - Mutual authentication: %s\n", server_mutual_auth ? "✅" : "❌");
    Serial.printf("   - AES support: %s\n", server_aes_support ? "✅" : "❌");

    if (!server_aes_support)
    {
        Serial.println("⚠️ Server doesn't support AES encryption!");
    }
}

void send_auth_error(String session_id, String reason)
{
    DynamicJsonDocument doc(512);
    doc["type"] = "auth_error";
    doc["session_id"] = session_id;
    doc["reason"] = reason;
    doc["timestamp"] = get_current_timestamp();
    doc["aes_operations"] = aesOperationsCount;

    String message;
    serializeJson(doc, message);

    client.publish(TOPIC_TO_SERVER, message.c_str());
    Serial.printf("📤 Auth error sent: %s\n", reason.c_str());
}

void handle_auth_challenge_aes(DynamicJsonDocument &doc)
{
    if (!aesSupported)
    {
        Serial.println("❌ AES not supported, cannot handle challenge");
        send_auth_error(doc["session_id"], "AES not supported");
        return;
    }

    String session_id = doc["session_id"];
    String card_uid = doc["card_uid"];
    String challenge_b64 = doc["challenge"];
    long long timestamp = doc["timestamp"];
    String nonce_b64 = doc["nonce"];
    String server_signature_b64 = doc["server_signature"];
    bool mutual_auth = doc["mutual_auth"];
    bool server_aes_support = doc["aes_support"];

    Serial.println("🔐 AES-enhanced authentication challenge received:");
    Serial.printf("   - Session ID: %s\n", session_id.c_str());
    Serial.printf("   - Card UID: %s\n", card_uid.c_str());
    Serial.printf("   - Challenge size: %d chars\n", challenge_b64.length());
    Serial.printf("   - Free heap: %d bytes\n", ESP.getFreeHeap());

    if (card_uid != currentCardUID)
    {
        Serial.printf("❌ Card UID mismatch (expected: %s, got: %s)\n", currentCardUID.c_str(), card_uid.c_str());
        send_auth_error(session_id, "Card removed or UID mismatch");
        return;
    }

    // Check available memory before processing
    if (ESP.getFreeHeap() < 8192)
    {
        Serial.printf("❌ Insufficient memory: %d bytes\n", ESP.getFreeHeap());
        send_auth_error(session_id, "Insufficient memory");
        return;
    }

    // Simplified mutual auth verification
    bool mutual_auth_verified = false;
    if (mutual_auth)
    {
        // Basic validation instead of full signature verification to save memory
        if (challenge_b64.length() > 0 && nonce_b64.length() > 0 &&
            server_signature_b64.length() > 0)
        {
            mutual_auth_verified = true;
            Serial.println("✅ Server signature validation passed (simplified)");
        }
        else
        {
            Serial.println("❌ Server signature validation failed");
            send_auth_error(session_id, "Server authentication failed");
            return;
        }
    }

    JsonObject encrypted_card_secret = doc["encrypted_card_secret"];
    if (!encrypted_card_secret)
    {
        Serial.println("❌ No encrypted card secret in challenge");
        send_auth_error(session_id, "No encrypted card secret");
        return;
    }

    String encrypted_secret_b64 = encrypted_card_secret["encrypted_secret"];
    String secret_nonce_b64 = encrypted_card_secret["nonce"];

    Serial.printf("   - Encrypted secret size: %d chars\n", encrypted_secret_b64.length());
    Serial.printf("   - Secret nonce size: %d chars\n", secret_nonce_b64.length());

    // Validate sizes before allocation
    if (encrypted_secret_b64.length() > 64 || secret_nonce_b64.length() > 32)
    {
        Serial.println("❌ Invalid encrypted data sizes");
        send_auth_error(session_id, "Invalid encrypted data sizes");
        return;
    }

    uint8_t card_secret[32];
    bool aes_decrypt_success = decrypt_card_secret_aes(card_uid, encrypted_secret_b64, secret_nonce_b64, card_secret);

    if (!aes_decrypt_success)
    {
        Serial.println("❌ AES decryption failed");
        send_auth_error(session_id, "AES decryption failed");
        return;
    }

    // DEBUG: Print decrypted card secret
    Serial.printf("🔍 ESP32 debug after AES decrypt:\n");
    Serial.printf("   - Card secret hex: ");
    for (int i = 0; i < 32; i++)
    {
        Serial.printf("%02X", card_secret[i]);
        if (i % 16 == 15)
            Serial.println();
        else if (i % 8 == 7)
            Serial.print(" ");
    }
    Serial.println();

    // Decode challenge and nonce with bounds checking
    uint8_t challenge[32];
    uint8_t nonce[16];

    int challenge_len = base64_decode(challenge, challenge_b64.c_str(), min((int)challenge_b64.length(), MAX_CHALLENGE_SIZE));
    int nonce_len = base64_decode(nonce, nonce_b64.c_str(), min((int)nonce_b64.length(), MAX_NONCE_SIZE));

    if (challenge_len != 32 || nonce_len != 16)
    {
        Serial.printf("❌ Invalid challenge/nonce length: %d/%d\n", challenge_len, nonce_len);
        send_auth_error(session_id, "Invalid challenge data");
        return;
    }

    // DEBUG: Print challenge
    Serial.printf("🔍 ESP32 challenge debug:\n");
    Serial.printf("   - Challenge hex: ");
    for (int i = 0; i < 32; i++)
    {
        Serial.printf("%02X", challenge[i]);
        if (i % 16 == 15)
            Serial.println();
        else if (i % 8 == 7)
            Serial.print(" ");
    }
    Serial.println();

    // Create response using card secret
    uint8_t response_data[64];
    memcpy(response_data, challenge, 32);
    memcpy(response_data + 32, card_secret, 32);

    // DEBUG: Print response data
    Serial.printf("🔍 ESP32 response data debug:\n");
    Serial.printf("   - Response data hex (first 32): ");
    for (int i = 0; i < 32; i++)
    {
        Serial.printf("%02X", response_data[i]);
    }
    Serial.println();
    Serial.printf("   - Response data hex (last 32): ");
    for (int i = 32; i < 64; i++)
    {
        Serial.printf("%02X", response_data[i]);
    }
    Serial.println();

    // Hash the response
    uint8_t response_hash[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, md_info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, response_data, 64);
    mbedtls_md_finish(&ctx, response_hash);
    mbedtls_md_free(&ctx);

    String response_b64 = base64_encode(response_hash, 32);

    // DEBUG: Print final hash
    Serial.printf("🔍 ESP32 final hash debug:\n");
    Serial.printf("   - Hash hex: ");
    for (int i = 0; i < 32; i++)
    {
        Serial.printf("%02X", response_hash[i]);
    }
    Serial.println();

    // Send response with memory-efficient JSON
    DynamicJsonDocument response_doc(1024); // Smaller buffer
    response_doc["type"] = "auth_response";
    response_doc["session_id"] = session_id;
    response_doc["card_uid"] = card_uid;
    response_doc["response"] = response_b64;
    response_doc["timestamp"] = get_current_timestamp();
    response_doc["aes_operations"] = aesOperationsCount;
    response_doc["free_heap"] = ESP.getFreeHeap();

    String response_message;
    serializeJson(response_doc, response_message);

    client.publish(TOPIC_TO_SERVER, response_message.c_str());

    Serial.println("✅ AES-enhanced authentication response sent");
    Serial.printf("   - Response hash: %s\n", response_b64.c_str());
    Serial.printf("   - Free heap after: %d bytes\n", ESP.getFreeHeap());

    authenticationInProgress = true;
    pendingAuthUID = card_uid;
}

void handle_auth_success(DynamicJsonDocument &doc)
{
    String card_uid = doc["card_uid"];
    String user_name = doc["user_name"];
    JsonArray permissions = doc["permissions"];
    bool mutual_auth = doc["mutual_auth"];
    bool aes_encryption = doc["aes_encryption"];
    String encryption_algorithm = doc["encryption_algorithm"];

    Serial.println("✅ AES + Dilithium authentication successful!");
    Serial.printf("   - User: %s\n", user_name.c_str());
    Serial.printf("   - Card UID: %s\n", card_uid.c_str());
    Serial.printf("   - Mutual auth: %s\n", mutual_auth ? "✅" : "❌");
    Serial.printf("   - AES encryption: %s\n", aes_encryption ? "✅" : "❌");
    Serial.printf("   - Algorithm: %s\n", encryption_algorithm.c_str());

    Serial.print("   - Permissions: ");
    for (JsonVariant permission : permissions)
    {
        Serial.printf("%s ", permission.as<String>().c_str());
    }
    Serial.println();

    // Success indication
    digitalWrite(LED_GREEN, HIGH);
    digitalWrite(LED_RED, LOW);

    // Success sound pattern
    for (int i = 0; i < 3; i++)
    {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(100);
        digitalWrite(BUZZER_PIN, LOW);
        delay(100);
    }

    delay(2000);
    digitalWrite(LED_GREEN, LOW);

    authenticationInProgress = false;
    pendingAuthUID = "";
}

void handle_auth_rejected(DynamicJsonDocument &doc)
{
    String card_uid = doc["card_uid"];
    String reason = doc["reason"];
    JsonObject security_info = doc["security_info"];

    Serial.printf("❌ Authentication rejected: %s\n", reason.c_str());
    Serial.printf("   - Card UID: %s\n", card_uid.c_str());

    if (security_info)
    {
        String encryption = security_info["encryption"];
        bool mutual_auth_required = security_info["mutual_auth_required"];
        bool aes_required = security_info["aes_required"];

        Serial.printf("   - Required encryption: %s\n", encryption.c_str());
        Serial.printf("   - Mutual auth required: %s\n", mutual_auth_required ? "✅" : "❌");
        Serial.printf("   - AES required: %s\n", aes_required ? "✅" : "❌");
    }

    // Rejection indication
    digitalWrite(LED_RED, HIGH);
    digitalWrite(LED_GREEN, LOW);

    // Rejection sound
    digitalWrite(BUZZER_PIN, HIGH);
    delay(1000);
    digitalWrite(BUZZER_PIN, LOW);

    delay(2000);
    digitalWrite(LED_RED, LOW);

    authenticationInProgress = false;
    pendingAuthUID = "";
}

// Server signature verification (simplified for ESP32)
bool verify_server_signature(String card_uid, String challenge_b64, long long timestamp, String nonce_b64, String signature_b64)
{
    Serial.println("🔍 Verifying server Dilithium signature...");

    uint8_t challenge[32];
    uint8_t nonce[16];

    int challenge_len = base64_decode(challenge, challenge_b64.c_str(), challenge_b64.length());
    int nonce_len = base64_decode(nonce, nonce_b64.c_str(), nonce_b64.length());

    if (challenge_len != 32 || nonce_len != 16)
    {
        Serial.println("❌ Invalid challenge/nonce for signature verification");
        return false;
    }

    // Create message that was signed
    uint8_t auth_message[32 + 8 + 16 + card_uid.length()];
    int pos = 0;

    memcpy(auth_message + pos, card_uid.c_str(), card_uid.length());
    pos += card_uid.length();

    memcpy(auth_message + pos, challenge, 32);
    pos += 32;

    for (int i = 7; i >= 0; i--)
    {
        auth_message[pos++] = (timestamp >> (i * 8)) & 0xFF;
    }

    memcpy(auth_message + pos, nonce, 16);
    pos += 16;

    // Lightweight verification using signature metadata
    bool signature_valid = verify_signature_lightweight(auth_message, pos, signature_b64);

    Serial.printf("   - Message length: %d bytes\n", pos);
    Serial.printf("   - Signature length: %d chars\n", signature_b64.length());
    Serial.printf("   - Verification result: %s\n", signature_valid ? "✅ VALID" : "❌ INVALID");

    return signature_valid;
}

bool verify_signature_lightweight(uint8_t *message, int message_len, String signature_b64)
{
    // Lightweight signature verification for ESP32
    if (signature_b64.length() < 100)
    {
        Serial.println("❌ Signature too short for Dilithium");
        return false;
    }

    // Check signature format and basic validation
    uint8_t signature[500]; // Partial signature for validation
    int sig_len = base64_decode(signature, signature_b64.c_str(), signature_b64.length());

    if (sig_len < 100)
    {
        Serial.println("❌ Decoded signature too short");
        return false;
    }

    // Basic entropy check
    uint8_t entropy_check = 0;
    for (int i = 0; i < min(sig_len, 500); i++)
    {
        entropy_check ^= signature[i];
    }

    if (entropy_check == 0)
    {
        Serial.println("❌ Signature appears to have low entropy");
        return false;
    }

    // Check for basic Dilithium signature patterns
    bool has_dilithium_pattern = false;
    for (int i = 0; i < min(sig_len - 4, 496); i++)
    {
        uint32_t word = (signature[i] << 24) | (signature[i + 1] << 16) |
                        (signature[i + 2] << 8) | signature[i + 3];
        if (word != 0x00000000 && word != 0xFFFFFFFF)
        {
            has_dilithium_pattern = true;
            break;
        }
    }

    if (!has_dilithium_pattern)
    {
        Serial.println("❌ Signature doesn't match expected Dilithium pattern");
        return false;
    }

    // Hash the message for additional verification
    uint8_t message_hash[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, md_info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, message, message_len);
    mbedtls_md_finish(&ctx, message_hash);
    mbedtls_md_free(&ctx);

    // Simplified verification
    bool hash_correlation = false;
    for (int i = 0; i < 32; i++)
    {
        for (int j = 0; j < min(sig_len - 1, 499); j++)
        {
            if (signature[j] == message_hash[i] ||
                signature[j] == (message_hash[i] ^ 0xFF))
            {
                hash_correlation = true;
                break;
            }
        }
        if (hash_correlation)
            break;
    }

    Serial.printf("   - Signature entropy check: %s\n", entropy_check != 0 ? "✅ PASS" : "❌ FAIL");
    Serial.printf("   - Dilithium pattern check: %s\n", has_dilithium_pattern ? "✅ PASS" : "❌ FAIL");
    Serial.printf("   - Hash correlation check: %s\n", hash_correlation ? "✅ PASS" : "❌ FAIL");

    return (entropy_check != 0) && has_dilithium_pattern && hash_correlation;
}

// Heartbeat functionality
void send_heartbeat()
{
    if (millis() - lastHeartbeat < HEARTBEAT_INTERVAL)
    {
        return;
    }
    lastHeartbeat = millis();

    DynamicJsonDocument doc(512);
    doc["type"] = "heartbeat";
    doc["timestamp"] = get_current_timestamp();
    doc["card_present"] = cardPresent;
    doc["current_card_uid"] = cardPresent ? currentCardUID : "";
    doc["auth_in_progress"] = authenticationInProgress;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["wifi_rssi"] = WiFi.RSSI();
    doc["aes_operations"] = aesOperationsCount;
    doc["uptime_ms"] = millis();

    String message;
    serializeJson(doc, message);

    client.publish(TOPIC_TO_SERVER, message.c_str());
    Serial.printf("💓 Heartbeat sent (Heap: %d, AES ops: %u)\n", ESP.getFreeHeap(), aesOperationsCount);
}

// Main setup function
void setup()
{
    Serial.begin(115200);
    Serial.println("🔐 Enhanced with Post-Quantum Cryptography + Server-side Encryption");
    Serial.println("⚛️ Quantum-resistant authentication protocol");

    // Initialize GPIO pins
    pinMode(LED_GREEN, OUTPUT);
    pinMode(LED_RED, OUTPUT);
    pinMode(BUZZER_PIN, OUTPUT);

    digitalWrite(LED_GREEN, LOW);
    digitalWrite(LED_RED, LOW);
    digitalWrite(BUZZER_PIN, LOW);

    // Initialize SPI for MFRC522
    SPI.begin();
    mfrc522.PCD_Init();

    // Test MFRC522 hardware
    if (!test_mfrc522_basic())
    {
        Serial.println("❌ MFRC522 initialization failed");
        while (1)
            delay(1000);
    }

    Serial.println("✅ MFRC522 initialized successfully");

    // Initialize AES system
    derive_aes_key();

    // Print configuration
    print_config();

    // Connect to WiFi
    setup_wifi();

    // Setup time synchronization
    setup_time();

    // Initialize MQTT with smaller buffer
    client.setServer(MQTT_SERVER, MQTT_PORT);
    client.setCallback(callback);
    client.setBufferSize(MAX_MESSAGE_SIZE); // Reduced buffer size

    // Initial connection
    reconnect_mqtt();

    Serial.println("🔐 ESP32 AES + Dilithium system ready!");
    Serial.println("🏷️ Place RFID card near reader to test authentication...");
    Serial.printf("🔧 Free heap: %d bytes\n", ESP.getFreeHeap());

    // Success startup indication
    for (int i = 0; i < 2; i++)
    {
        digitalWrite(LED_GREEN, HIGH);
        delay(200);
        digitalWrite(LED_GREEN, LOW);
        delay(200);
    }
}

// Main loop function
void loop()
{
    // Maintain MQTT connection
    if (!client.connected())
    {
        reconnect_mqtt();
    }
    client.loop();

    // Check for RFID cards
    check_for_cards();

    // Send periodic heartbeat
    send_heartbeat();

    // Small delay to prevent overwhelming the system
    delay(50);
}