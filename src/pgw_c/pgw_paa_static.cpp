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

/*! \file pgw_paa_static.cpp
  \brief Static PDN address allocation
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "common_defs.h"

#include "logger.hpp"
#include "pgw_app.hpp"
#include "pgw_config.hpp"

#include <string>

using namespace oai::cn::nf::pgwc;
using namespace oai::cn::core;

extern pgw_config pgw_cfg;

//------------------------------------------------------------------------------
int pgw_app::static_paa_get_free_paa (const std::string& apn, paa_t& paa)
{
  int pool_id_ipv4 = -1;
  int pool_id_ipv6 = -1;
  int ret = pgw_cfg.get_pa_pool_id(apn, pool_id_ipv4, pool_id_ipv6);
  if (RETURNok == ret) {
    if (paa.pdn_type.pdn_type == PDN_TYPE_E_IPV4) {
      if ((pool_id_ipv4 >= 0) && (pool_id_ipv4 < PGW_NUM_UE_POOL_MAX)) {
        if (ipv4_pool_list[pool_id_ipv4].size() >= 1) {
          paa.ipv4_address = ipv4_pool_list[pool_id_ipv4].front();
          return RETURNok;
        } else return RETURNerror;
      }
    } else if (paa.pdn_type.pdn_type == PDN_TYPE_E_IPV4V6) {
      if ((pool_id_ipv4 >= 0) && (pool_id_ipv4 < PGW_NUM_UE_POOL_MAX)) {
        if (ipv4_pool_list[pool_id_ipv4].size() >= 1) {
          paa.ipv4_address = ipv4_pool_list[pool_id_ipv4].front();
        }
      }
      if ((pool_id_ipv6 >= 0) && (pool_id_ipv6 < PGW_NUM_UE_POOL_MAX)) {
        paa.ipv6_address = pgw_cfg.paa_pool6_prefix[pool_id_ipv6];
        paa.ipv6_prefix_length = pgw_cfg.paa_pool6_prefix_len[pool_id_ipv6];
      }
      // TODO check when fine to return OK
      if ((pool_id_ipv4 < 0) && (pool_id_ipv6 < 0)) return RETURNerror;
      return RETURNok;
    } else if (paa.pdn_type.pdn_type == PDN_TYPE_E_IPV6) {
      if ((pool_id_ipv6 >= 0) && (pool_id_ipv6 < PGW_NUM_UE_POOL_MAX)) {
        paa.ipv6_address = pgw_cfg.paa_pool6_prefix[pool_id_ipv6];
        paa.ipv6_prefix_length = pgw_cfg.paa_pool6_prefix_len[pool_id_ipv6];
        return RETURNok;
      }
    }
  }
  return RETURNerror;
}
//------------------------------------------------------------------------------
int pgw_app::static_paa_release_address (const std::string& apn, struct in_addr& addr)
{
  int pool_id_ipv4 = -1;
  int pool_id_ipv6 = -1;
  int ret = pgw_cfg.get_pa_pool_id(apn, pool_id_ipv4, pool_id_ipv6);
  if (RETURNok == ret) {
    if ((pool_id_ipv4 >= 0) && (pool_id_ipv4 < PGW_NUM_UE_POOL_MAX)) {
      ipv4_pool_list[pool_id_ipv4].push_back(addr);
      addr.s_addr = INADDR_ANY;
      return RETURNok;
    }
  }
  return RETURNerror;
}

//------------------------------------------------------------------------------
int pgw_app::static_paa_get_num_ipv4_pool(void)
{
  return num_ue_pool;
}

//------------------------------------------------------------------------------
int pgw_app::static_paa_get_ipv4_pool(const int pool_id, struct in_addr * const range_low, struct in_addr * const range_high, struct in_addr * const netaddr, struct in_addr * const netmask, std::vector<struct in_addr>::iterator& it_out_of_nw)
{
  // Only one block supported now (have to process the release in right pool)
  if (pool_id < pgw_cfg.num_ue_pool) {
    if (range_low) {
      *range_low = pgw_cfg.ue_pool_range_low[pool_id];
    }
    if (range_high) {
      *range_high = pgw_cfg.ue_pool_range_high[pool_id];
    }
    if (netaddr) {
      *netaddr = pgw_cfg.ue_pool_network[pool_id];
    }
    if (netmask) {
      *netmask = pgw_cfg.ue_pool_netmask[pool_id];
    }
    it_out_of_nw = pgw_cfg.ue_pool_excluded[pool_id].begin();
    return RETURNok;
  }
  return RETURNerror;
}


//------------------------------------------------------------------------------
int pgw_app::static_paa_get_pool_id(const struct in_addr& ue_addr)
{
  for (int i = 0; i < pgw_cfg.num_ue_pool; i++) {
    if ((ntohl(ue_addr.s_addr) >= ntohl(pgw_cfg.ue_pool_range_low[i].s_addr)) &&
        (ntohl(ue_addr.s_addr) <= ntohl(pgw_cfg.ue_pool_range_high[i].s_addr))) {
      return i;
    }
  }
  return -1;
}
