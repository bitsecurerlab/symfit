#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void telemetry_init(const char *ip_addr, unsigned short port);
void telemetry_send(const char *json);
void telemetry_shutdown(void);
extern char telemetry_enabled;

#ifdef __cplusplus
}
#endif
