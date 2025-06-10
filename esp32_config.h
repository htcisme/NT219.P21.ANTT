#ifndef CONFIG_H
#define CONFIG_H

// Auto-generated configuration for ESP32 Dilithium UID RFID
// Generated: 2025-06-09T19:28:03.642694

// WiFi Configuration
#define WIFI_SSID "Pandora"
#define WIFI_PASSWORD "12345678"
#define MQTT_SERVER "192.168.137.221"
#define MQTT_PORT 1883

// MQTT Topics
#define TOPIC_TO_SERVER "rfid/esp32_to_server"
#define TOPIC_FROM_SERVER "rfid/server_to_esp32"

// Dilithium Configuration
#define SIG_ALGORITHM "Dilithium2"
#define CHALLENGE_SIZE 32
#define TIMESTAMP_TOLERANCE 60
#define SESSION_TIMEOUT 30
#define MUTUAL_AUTHENTICATION true

// AES Configuration (UPDATED)
#define AES_NONCE_SIZE 16 // 128-bit nonce for CTR mode
#define AES_KEY_SIZE 16   // 128-bit AES key

// Server Public Key (Dilithium2)
#define DILITHIUM_PUBLIC_KEY_SIZE 1312

#endif