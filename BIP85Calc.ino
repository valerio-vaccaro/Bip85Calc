#include "SPI.h"
#include "TFT_eSPI.h"
#include <Keypad.h>
#include <string.h>
#include <stdlib.h>
#include "qrcoded.h"
#include <WiFi.h>
#include "esp_adc_cal.h"
#include "MyFont.h"
#include "MySd.h"
#include "MyUtils.h"

#include "secp256k1.h"
#include "wally_core.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include "wally_address.h"
#include "wally_crypto.h"
#include "mbedtls/md.h"

#define BIGFONT &FreeMonoBold24pt7b
#define MIDBIGFONT &FreeMonoBold18pt7b
#define MIDFONT &FreeMonoBold12pt7b
#define SMALLFONT &FreeMonoBold9pt7b
#define TINYFONT &TomThumb

bool isLilyGoKeyboard = true;
bool isSleepEnabled = true;
int sleepTimer = 30; // Time in seconds before the device goes to sleep
int qrScreenBrightness = 180; // 0 = min, 255 = max
const bool shouldDisplayBatteryLevel = true; // Display the battery level on the display?
const float batteryMaxVoltage = 4.2; // The maximum battery voltage. Used for battery percentage calculation
const float batteryMinVoltage = 3.73; // The minimum battery voltage that we tolerate before showing the warning

String key_val;
String cntr = "0";
String inputs;
String virtkey;
int randomPin;
bool settle = false;
RTC_DATA_ATTR int bootCount = 0;
long timeOfLastInteraction = millis();
bool isPretendSleeping = false;

TFT_eSPI tft = TFT_eSPI();

const byte rows = 4; //four rows
const byte cols = 3; //three columns
char keys[rows][cols] = {
  {'1', '2', '3'},
  {'4', '5', '6'},
  {'7', '8', '9'},
  {'*', '0', '#'}
};

//Big keypad setup
//byte rowPins[rows] = {12, 13, 15, 2}; //connect to the row pinouts of the keypad
//byte colPins[cols] = {17, 22, 21}; //connect to the column pinouts of the keypad

//LilyGO T-Display-Keyboard
byte rowPins[rows] = {21, 27, 26, 22}; //connect to the row pinouts of the keypad
byte colPins[cols] = {33, 32, 25}; //connect to the column pinouts of the keypad

// 4 x 4 keypad setup
//byte rowPins[rows] = {21, 22, 17, 2}; //connect to the row pinouts of the keypad
//byte colPins[cols] = {15, 13, 12}; //connect to the column pinouts of the keypad

//Small keypad setup
//byte rowPins[rows] = {21, 22, 17, 2}; //connect to the row pinouts of the keypad
//byte colPins[cols] = {15, 13, 12};    //connect to the column pinouts of the keypad

Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, rows, cols);
int checker = 0;
char maxdig[20];

ext_key root;

void setup(void) {
  Serial.begin(115200);
  pinMode(4, OUTPUT);
  digitalWrite(4, HIGH);

  btStop();
  WiFi.mode(WIFI_OFF);

  //h.begin();
  tft.begin();

  //Set to 3 for bigger keypad
  tft.setRotation(1);
  if (bootCount == 0)
  {
    logo();
    delay(3000);
  }
  else
  {
    wakeAnimation();
  }
  ++bootCount;
  Serial.println("Boot count" + bootCount);

  SPI.begin(SD_SCLK, SD_MISO, SD_MOSI, SD_CS);
  if (!SD.begin(SD_CS)) {
    Serial.println("SDCard MOUNT FAIL");
  } else {
    uint32_t cardSize = SD.cardSize() / (1024 * 1024);
    String str = "SDCard Size: " + String(cardSize) + "MB";
    Serial.println(str);
  }


  uint8_t cardType = SD.cardType();

  if (cardType == CARD_NONE) {
    Serial.println("No SD card attached");
    return;
  }

  Serial.print("SD Card Type: ");
  if (cardType == CARD_MMC) {
    Serial.println("MMC");
  } else if (cardType == CARD_SD) {
    Serial.println("SDSC");
  } else if (cardType == CARD_SDHC) {
    Serial.println("SDHC");
  } else {
    Serial.println("UNKNOWN");
  }

  uint64_t cardSize = SD.cardSize() / (1024 * 1024);
  Serial.printf("SD Card Size: %lluMB\n", cardSize);
}

void bip85_derive(uint32_t index, char ** result_mnemonic) {
  String mnemonic = "cup hunt peanut afford cute bridge bread immense artist story funny wrap weather weather monster duck spray gasp adjust clerk rather engage mind craft";
  writeFile(SD, "/master_mnemonic.txt", mnemonic.c_str());
  String mnemonic2 = readFile(SD, "/master_mnemonic.txt");

  //String master_password = "";
  //writeFile(SD, "/master_password.txt", master_password.c_str());
  String master_password = readFile(SD, "/master_password.txt");

  // converting recovery phrase to seed
  int res;
  size_t len;
  uint8_t seed[BIP39_SEED_LEN_512];
  res = bip39_mnemonic_to_seed(mnemonic.c_str(), master_password.c_str(), seed, sizeof(seed), &len);

  Serial.print("Seed: ");
  println_hex(seed, sizeof(seed));

  res = bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0, &root);
  // get base58 xprv string
  char *xprv = NULL;
  res = bip32_key_to_base58(&root, BIP32_FLAG_KEY_PRIVATE, &xprv);
  Serial.print("Root key: ");
  Serial.println(xprv);

  ext_key account;
  uint32_t path[] = {
    BIP32_INITIAL_HARDENED_CHILD + 83696968, // 83696968h
    BIP32_INITIAL_HARDENED_CHILD + 39,      // 39h
    BIP32_INITIAL_HARDENED_CHILD,          // 0h
    BIP32_INITIAL_HARDENED_CHILD + 12,     // 12h
    BIP32_INITIAL_HARDENED_CHILD + index   // index hardened
  };

  res = bip32_key_from_parent_path(&root, path, 5, BIP32_FLAG_KEY_PRIVATE, &account);
  char *xprv_acc = NULL;
  res = bip32_key_to_base58(&account, BIP32_FLAG_KEY_PRIVATE, &xprv_acc);
  Serial.print("Account key: ");
  Serial.println(xprv_acc);

  unsigned char account_key[32];
  Serial.println(sizeof(account.priv_key));
  memcpy(account_key, account.priv_key + 1, sizeof(account.priv_key) - 1);
  Serial.print("Account key: ");
  for (int i = 0; i < sizeof(account_key); i++) {
    Serial.print(account_key[i], HEX);
  }

  // calclulate entropy
  byte hmacResult[64];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA512;
  String message = "bip-entropy-from-k";
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *) message.c_str(), 18);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *) account_key, sizeof(account_key));
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  Serial.print("\nEntropy: ");
  for (int i = 0; i < sizeof(hmacResult); i++) {
    Serial.print(hmacResult[i], HEX);
  }
  Serial.println();

  Serial.print("Mnemonic: ");
  res = bip39_mnemonic_from_bytes(NULL, hmacResult, 16, result_mnemonic);
  Serial.println(*result_mnemonic);
}

void loop() {
  digitalWrite(4, HIGH);
  maybeSleepDevice();
  inputs = "";
  settle = false;
  displayDerivation();
  bool cntr = false;

  while (cntr != true) {
    maybeSleepDevice();
    displayBatteryVoltage(false);
    char key = keypad.getKey();
    if (key != NO_KEY)
    {
      isPretendSleeping = false;
      timeOfLastInteraction = millis();
      virtkey = String(key);
      if (virtkey == "#") {
        char * mnemonic;
        bip85_derive(atoi(inputs.c_str()), &mnemonic);
        qrShowCode(String(mnemonic));
        int counta = 0;
        while (settle != true) {
          virtkey = String(keypad.getKey());
          if (virtkey == "*") {
            timeOfLastInteraction = millis();
            tft.fillScreen(TFT_BLACK);
            settle = true;
            cntr = true;
          }
          // Handle screen brighten on QR screen
          else if (virtkey == "1") {
            timeOfLastInteraction = millis();
            adjustQrBrightness(String(mnemonic), "increase");
          }
          // Handle screen dim on QR screen
          else if (virtkey == "4") {
            timeOfLastInteraction = millis();
            adjustQrBrightness(String(mnemonic), "decrease");
          }
        }
        wally_free_string(mnemonic);
      }
      else if (virtkey == "*")
      {
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(0, 0);
        tft.setTextColor(TFT_WHITE);
        key_val = "";
        inputs = "";
        virtkey = "";
        cntr = "2";
      }
      displayDerivation();
    }
  }
}

// QR screen colours
uint16_t qrScreenBgColour = tft.color565(qrScreenBrightness, qrScreenBrightness, qrScreenBrightness);

void adjustQrBrightness(String mnemonic, String direction)
{
  if (direction == "increase" && qrScreenBrightness >= 0)
  {
    qrScreenBrightness = qrScreenBrightness + 25;
    if (qrScreenBrightness > 255)
    {
      qrScreenBrightness = 255;
    }
  }
  else if (direction == "decrease" && qrScreenBrightness <= 30)
  {
    qrScreenBrightness = qrScreenBrightness - 5;
  }
  else if (direction == "decrease" && qrScreenBrightness <= 255)
  {
    qrScreenBrightness = qrScreenBrightness - 25;
  }

  if (qrScreenBrightness < 4)
  {
    qrScreenBrightness = 4;
  }

  qrScreenBgColour = tft.color565(qrScreenBrightness, qrScreenBrightness, qrScreenBrightness);
  qrShowCode(mnemonic);
}

void qrShowCode(String mnemonic)
{
  tft.fillScreen(qrScreenBgColour);
  mnemonic.toUpperCase();
  const char *mnemonicChar = mnemonic.c_str();
  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(20)];
  qrcode_initText(&qrcode, qrcodeData, 6, ECC_HIGH, mnemonicChar);
  for (uint8_t y = 0; y < qrcode.size; y++)
  {
    // Each horizontal module
    for (uint8_t x = 0; x < qrcode.size; x++)
    {
      if (qrcode_getModule(&qrcode, x, y))
      {
        tft.fillRect(60 + 3 * x, 5 + 3 * y, 3, 3, TFT_BLACK);
      }
      else
      {
        tft.fillRect(60 + 3 * x, 5 + 3 * y, 3, 3, qrScreenBgColour);
      }
    }
  }
}

void displayDerivation()
{
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK); // White characters on black background
  tft.setFreeFont(MIDFONT);
  tft.setCursor(0, 20);
  tft.println("BIP85 ---");
  tft.setCursor(40, 110);
  tft.setFreeFont(SMALLFONT);
  tft.println("TO CONFIRM PRESS #");
  tft.setCursor(40, 130);
  tft.setFreeFont(SMALLFONT);
  tft.println("TO RESET PRESS *");

  inputs += virtkey;

  tft.setFreeFont(MIDFONT);
  tft.setCursor(0, 80);
  tft.print("INDEX :");
  tft.setFreeFont(MIDBIGFONT);
  tft.setTextColor(TFT_GREEN, TFT_BLACK);

  int amount = inputs.toInt();
  tft.println(amount);

  displayBatteryVoltage(true);
  delay(50);
  virtkey = "";
}

void logo()
{
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setFreeFont(BIGFONT);
  tft.setCursor(1, 70);
  tft.print(" BIP 85");

  tft.setTextColor(TFT_GREEN, TFT_BLACK);
  tft.setFreeFont(SMALLFONT);
  tft.setCursor(5, 90);
  tft.print("Valerio Vaccaro 2022");
}

long lastBatteryUpdate = millis();
int batteryLevelUpdatePeriod = 10; // update every X seconds
/**
   Display the battery voltage
*/
void displayBatteryVoltage(bool forceUpdate)
{
  long currentTime = millis();
  if (
    (shouldDisplayBatteryLevel
     &&
     (currentTime > (lastBatteryUpdate + batteryLevelUpdatePeriod * 1000))
     &&
     !isPoweredExternally()
    )
    ||
    (shouldDisplayBatteryLevel && forceUpdate && !isPoweredExternally())
  )
  {
    lastBatteryUpdate = currentTime;
    bool showBatteryVoltage = false;
    float batteryCurV = getInputVoltage();
    float batteryAllowedRange = batteryMaxVoltage - batteryMinVoltage;
    float batteryCurVAboveMin = batteryCurV - batteryMinVoltage;

    int batteryPercentage = (int)(batteryCurVAboveMin / batteryAllowedRange * 100);

    if (batteryPercentage > 100) {
      batteryPercentage = 100;
    }

    int textColour = TFT_GREEN;
    if (batteryPercentage > 70) {
      textColour = TFT_GREEN;
    }
    else if (batteryPercentage > 30)
    {
      textColour = TFT_YELLOW;
    }
    else
    {
      textColour = TFT_RED;
    }

    tft.setTextColor(textColour, TFT_BLACK);
    tft.setFreeFont(SMALLFONT);

    int textXPos = 195;
    if (batteryPercentage < 100) {
      textXPos = 200;
    }

    // Clear the area of the display where the battery level is shown
    tft.fillRect(textXPos - 2, 0, 50, 20, TFT_BLACK);
    tft.setCursor(textXPos, 16);

    // Is the device charging?
    if (isPoweredExternally()) {
      tft.print("CHRG");
    }
    // Show the current voltage
    if (batteryPercentage > 10) {
      tft.print(String(batteryPercentage) + "%");
    }
    else {
      tft.print("LOW");
    }

    if (showBatteryVoltage) {
      tft.setFreeFont(SMALLFONT);
      tft.setCursor(155, 36);
      tft.print(String(batteryCurV) + "v");
    }
  }
}

void maybeSleepDevice() {
  if (isSleepEnabled && !isPretendSleeping) {
    long currentTime = millis();
    if (currentTime > (timeOfLastInteraction + sleepTimer * 1000)) {
      sleepAnimation();
      // The device wont charge if it is sleeping, so when charging, do a pretend sleep
      if (isPoweredExternally()) {
        Serial.println("Pretend sleep now");
        isPretendSleeping = true;
        tft.fillScreen(TFT_BLACK);
      }
      else {
        if (isLilyGoKeyboard) {
          esp_sleep_enable_ext0_wakeup(GPIO_NUM_33, 1); //1 = High, 0 = Low
        } else {
          //Configure Touchpad as wakeup source
          touchAttachInterrupt(T3, callback, 40);
          esp_sleep_enable_touchpad_wakeup();
        }
        Serial.println("Going to sleep now");
        esp_deep_sleep_start();
      }
    }
  }
}

void callback() {
}

void sleepAnimation() {
  printSleepAnimationFrame("(o.o)", 500);
  printSleepAnimationFrame("(-.-)", 500);
  printSleepAnimationFrame("(-.-)z", 250);
  printSleepAnimationFrame("(-.-)zz", 250);
  printSleepAnimationFrame("(-.-)zzz", 250);
  digitalWrite(4, LOW);
}

void wakeAnimation() {
  printSleepAnimationFrame("(-.-)", 100);
  printSleepAnimationFrame("(o.o)", 200);
  tft.fillScreen(TFT_BLACK);
}

void printSleepAnimationFrame(String text, int wait) {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(5, 80);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setFreeFont(BIGFONT);
  tft.println(text);
  delay(wait);
}
