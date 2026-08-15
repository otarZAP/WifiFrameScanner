#pragma once
#include <RadioLib.h>
#include "net_tracker.h"

void loraReporterInit(SX1262* radio);

// Periodic summary — call from loop(), fires on LORA_SUMMARY_MS interval
void loraReporterTick(uint8_t channel, bool hopping,
                      uint8_t ap_count, uint8_t client_count,
                      uint32_t frame_total, uint32_t deauth_count);

// Event-driven reports
void loraReporterNewAp(const ApRecord* ap);
void loraReporterDeauth(const DeauthEvent* ev);
void loraReporterNewClient(const ClientRecord* client);

int16_t loraReporterLastRssi();
bool    loraReporterReady();
