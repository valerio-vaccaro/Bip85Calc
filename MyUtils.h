float getInputVoltage() {
  delay(100);
  uint16_t v1 = analogRead(34);
  return ((float)v1 / 4095.0f) * 2.0f * 3.3f * (1100.0f / 1000.0f);
}

bool isPoweredExternally() {
  float inputVoltage = getInputVoltage();
  if (inputVoltage > 4.5) return true;
  else return false;
}

void print_hex(const uint8_t * data, size_t data_len) {
  char arr[3];
  for (int i = 0; i < data_len; i++) {
    if (data[i] < 0x10) {
      Serial.print("0");
    }
    Serial.print(data[i], HEX);
  }
}

// just adds a new line to the end of the data
void println_hex(const uint8_t * data, size_t data_len) {
  print_hex(data, data_len);
  Serial.println();
}
