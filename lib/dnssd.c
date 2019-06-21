/*
 * Copyright (c) 2019 dsafa22, All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <malloc.h>
#include <assert.h>
#ifdef __ANDROID__
#include <endian.h>
#endif
#include <string.h>
#include "dnssd.h"
#include "log.h"
#include "utils.h"
#include "dnssdint.h"
#include "global.h"

#define MAX_DEVICEID 18
#define MAX_SERVNAME 256

struct dnssd_s {

    TXTRecordRef raop_record;
    TXTRecordRef airplay_record;

    DNSServiceRef raop_service;
    DNSServiceRef airplay_service;

    char *name;

    char *hw_addr;
    int hw_addr_len;
};

dnssd_t *
dnssd_init(const char* name, const char* hw_addr, int hw_addr_len, int *error)
{
    dnssd_t *dnssd;

    if (error) *error = DNSSD_ERROR_NOERROR;

    dnssd = calloc(1, sizeof(dnssd_t));
    if (!dnssd) {
        if (error) *error = DNSSD_ERROR_OUTOFMEM;
        return NULL;
    }
    dnssd->name = calloc(1, strlen(name) + 1);
    if (!dnssd->name) {
        free(dnssd);
        if (error) *error = DNSSD_ERROR_OUTOFMEM;
        return NULL;
    }
    strcpy(dnssd->name, name);

    dnssd->hw_addr_len = hw_addr_len;
    dnssd->hw_addr = calloc(1, dnssd->hw_addr_len);
    if (!dnssd->hw_addr) {
        free(dnssd->name);
        free(dnssd);
        if (error) *error = DNSSD_ERROR_OUTOFMEM;
        return NULL;
    }

    memcpy(dnssd->hw_addr, hw_addr, hw_addr_len);

    return dnssd;
}

int
dnssd_register_raop(dnssd_t *dnssd, unsigned short port)
{
    char servname[MAX_SERVNAME];

    assert(dnssd);

    TXTRecordCreate(&dnssd->raop_record, 0, NULL);
    TXTRecordSetValue(&dnssd->raop_record, "ch", strlen(RAOP_CH), RAOP_CH);
    TXTRecordSetValue(&dnssd->raop_record, "cn", strlen(RAOP_CN), RAOP_CN);
    TXTRecordSetValue(&dnssd->raop_record, "da", strlen(RAOP_DA), RAOP_DA);
    TXTRecordSetValue(&dnssd->raop_record, "et", strlen(RAOP_ET), RAOP_ET);
    TXTRecordSetValue(&dnssd->raop_record, "vv", strlen(RAOP_VV), RAOP_VV);
    TXTRecordSetValue(&dnssd->raop_record, "ft", strlen(RAOP_FT), RAOP_FT);
    TXTRecordSetValue(&dnssd->raop_record, "am", strlen(GLOBAL_MODEL), GLOBAL_MODEL);
    TXTRecordSetValue(&dnssd->raop_record, "md", strlen(RAOP_MD), RAOP_MD);
    TXTRecordSetValue(&dnssd->raop_record, "rhd", strlen(RAOP_RHD), RAOP_RHD);
    TXTRecordSetValue(&dnssd->raop_record, "pw", strlen("false"), "false");
    TXTRecordSetValue(&dnssd->raop_record, "sr", strlen(RAOP_SR), RAOP_SR);
    TXTRecordSetValue(&dnssd->raop_record, "ss", strlen(RAOP_SS), RAOP_SS);
    TXTRecordSetValue(&dnssd->raop_record, "sv", strlen(RAOP_SV), RAOP_SV);
    TXTRecordSetValue(&dnssd->raop_record, "tp", strlen(RAOP_TP), RAOP_TP);
    TXTRecordSetValue(&dnssd->raop_record, "txtvers", strlen(RAOP_TXTVERS), RAOP_TXTVERS);
    TXTRecordSetValue(&dnssd->raop_record, "sf", strlen(RAOP_SF), RAOP_SF);
    TXTRecordSetValue(&dnssd->raop_record, "vs", strlen(RAOP_VS), RAOP_VS);
    TXTRecordSetValue(&dnssd->raop_record, "vn", strlen(RAOP_VN), RAOP_VN);
    TXTRecordSetValue(&dnssd->raop_record, "pk", strlen(RAOP_PK), RAOP_PK);

    /* Convert hardware address to string */
    if (utils_hwaddr_raop(servname, sizeof(servname), dnssd->hw_addr, dnssd->hw_addr_len) < 0) {
        /* FIXME: handle better */
        return -1;
    }

    /* Check that we have bytes for 'hw@name' format */
    if (sizeof(servname) < strlen(servname) + 1 + strlen(dnssd->name)+ 1) {
        /* FIXME: handle better */
        return -2;
    }

    strncat(servname, "@", sizeof(servname)-strlen(servname)-1);
    strncat(servname, dnssd->name, sizeof(servname)-strlen(servname)-1);
    LOGD("servname = %s", servname);
    /* Register the service */
    DNSServiceErrorType err = DNSServiceRegister(&dnssd->raop_service, 0, 0,
                              servname, "_raop._tcp",
                              "local.", NULL,
                              htons(port),
                              TXTRecordGetLength(&dnssd->raop_record),
                              TXTRecordGetBytesPtr(&dnssd->raop_record),
                              NULL, NULL);
    if (err == kDNSServiceErr_NoError) {
        return DNSSD_ERROR_NOERROR;
    } else  if (err == kDNSServiceErr_ServiceNotRunning) {
        return DNSSD_ERROR_NOSERVICE;
    } else {
        return DNSSD_ERROR_OTHER;
    }
}

int
dnssd_register_airplay(dnssd_t *dnssd, unsigned short port)
{
    char device_id[3 * MAX_HWADDR_LEN];
    assert(dnssd);
    /* Convert hardware address to string */
    if (utils_hwaddr_airplay(device_id, sizeof(device_id), dnssd->hw_addr, dnssd->hw_addr_len) < 0) {
        /* FIXME: handle better */
        return -1;
    }
    TXTRecordCreate(&dnssd->airplay_record, 0, NULL);
    TXTRecordSetValue(&dnssd->airplay_record, "deviceid", strlen(device_id), device_id);
    TXTRecordSetValue(&dnssd->airplay_record, "features", strlen(AIRPLAY_FEATURES), AIRPLAY_FEATURES);
    TXTRecordSetValue(&dnssd->airplay_record, "srcvers", strlen(AIRPLAY_SRCVERS), AIRPLAY_SRCVERS);
    TXTRecordSetValue(&dnssd->airplay_record, "flags", strlen(AIRPLAY_FLAGS), AIRPLAY_FLAGS);
    TXTRecordSetValue(&dnssd->airplay_record, "vv", strlen(AIRPLAY_VV), AIRPLAY_VV);
    TXTRecordSetValue(&dnssd->airplay_record, "model", strlen(GLOBAL_MODEL), GLOBAL_MODEL);
    TXTRecordSetValue(&dnssd->airplay_record, "rhd", strlen(RAOP_RHD), RAOP_RHD);
    TXTRecordSetValue(&dnssd->airplay_record, "pw", strlen("false"), "false");
    TXTRecordSetValue(&dnssd->airplay_record, "pk", strlen(AIRPLAY_PK), AIRPLAY_PK);
    TXTRecordSetValue(&dnssd->airplay_record, "pi", strlen(AIRPLAY_PI), AIRPLAY_PI);
    LOGD("name = %s", dnssd->name);
    /* Register the service */
    DNSServiceErrorType err = DNSServiceRegister(&dnssd->airplay_service, 0, 0,
                              dnssd->name, "_airplay._tcp",
                              "local.", NULL,
                              htons(port),
                              TXTRecordGetLength(&dnssd->airplay_record),
                              TXTRecordGetBytesPtr(&dnssd->airplay_record),
                              NULL, NULL);
    if (err == kDNSServiceErr_NoError) {
        return DNSSD_ERROR_NOERROR;
    } else  if (err == kDNSServiceErr_ServiceNotRunning) {
        return DNSSD_ERROR_NOSERVICE;
    } else {
        return DNSSD_ERROR_OTHER;
    }
}

void
dnssd_unregister_raop(dnssd_t *dnssd)
{
    assert(dnssd);

    if (!dnssd->raop_service) {
        return;
    }

    /* Deallocate TXT record */
    TXTRecordDeallocate(&dnssd->raop_record);
    DNSServiceRefDeallocate(dnssd->raop_service);
    dnssd->raop_service = NULL;

    if (dnssd->airplay_service == NULL) {
        free(dnssd->name);
        free(dnssd->hw_addr);
    }
}

void
dnssd_unregister_airplay(dnssd_t *dnssd)
{
    assert(dnssd);

    if (!dnssd->airplay_service) {
        return;
    }

    /* Deallocate TXT record */
    TXTRecordDeallocate(&dnssd->airplay_record);
    DNSServiceRefDeallocate(dnssd->airplay_service);
    dnssd->airplay_service = NULL;

    if (dnssd->raop_service == NULL) {
        free(dnssd->name);
        free(dnssd->hw_addr);
    }
}

void
dnssd_destroy(dnssd_t *dnssd)
{
    if (dnssd) {
        free(dnssd);
    }
}