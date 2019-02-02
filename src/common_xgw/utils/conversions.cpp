/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file conversions.cpp
  \brief
  \author Sebastien ROUX
  \company Eurecom
*/
#include "conversions.hpp"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <inttypes.h>

static const char                       hex_to_ascii_table[16] = {
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static const signed char                ascii_to_hex_table[0x100] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

void
hexa_to_ascii (
  uint8_t * from,
  char *to,
  size_t length)
{
  size_t                                 i;

  for (i = 0; i < length; i++) {
    uint8_t                                 upper = (from[i] & 0xf0) >> 4;
    uint8_t                                 lower = from[i] & 0x0f;

    to[2 * i] = hex_to_ascii_table[upper];
    to[2 * i + 1] = hex_to_ascii_table[lower];
  }
}

int
ascii_to_hex (
  uint8_t * dst,
  const char *h)
{
  const unsigned char                    *hex = (const unsigned char *)h;
  unsigned                                i = 0;

  for (;;) {
    int                                     high,
                                            low;

    while (*hex && isspace (*hex))
      hex++;

    if (!*hex)
      return 1;

    high = ascii_to_hex_table[*hex++];

    if (high < 0)
      return 0;

    while (*hex && isspace (*hex))
      hex++;

    if (!*hex)
      return 0;

    low = ascii_to_hex_table[*hex++];

    if (low < 0)
      return 0;

    dst[i++] = (high << 4) | low;
  }
}
//------------------------------------------------------------------------------
imsi64_t imsi_to_imsi64(imsi_t * const imsi)
{
  imsi64_t imsi64 = INVALID_IMSI64;
  if (imsi) {
    imsi64 = 0;
    for (int i=0; i < IMSI_BCD8_SIZE; i++) {
      uint8_t d2 = imsi->u.value[i];
      uint8_t d1 = (d2 & 0xf0) >> 4;
      d2 = d2 & 0x0f;
      if (10 > d1) {
        imsi64 = imsi64*10 + d1;
        if (10 > d2) {
          imsi64 = imsi64*10 + d2;
        } else {
          break;
        }
      } else {
        break;
      }
    }
  }
  return imsi64;
}

//------------------------------------------------------------------------------
void paa_to_pfcp_ue_ip_address(const oai::cn::core::paa_t& paa, oai::cn::core::pfcp::ue_ip_address_t& ue_ip_address)
{
  switch (paa.pdn_type.pdn_type) {
  case oai::cn::core::PDN_TYPE_E_IPV4:
    ue_ip_address.v4 = 1;
    ue_ip_address.ipv4_address = paa.ipv4_address;
    break;
  case oai::cn::core::PDN_TYPE_E_IPV6:
    ue_ip_address.v6 = 1;
    ue_ip_address.ipv6_address = paa.ipv6_address;
    break;
  case oai::cn::core::PDN_TYPE_E_IPV4V6:
    ue_ip_address.v4 = 1;
    ue_ip_address.v6 = 1;
    ue_ip_address.ipv4_address = paa.ipv4_address;
    ue_ip_address.ipv6_address = paa.ipv6_address;
    break;
  case oai::cn::core::PDN_TYPE_E_NON_IP:
  default:
    ;
  }
}

