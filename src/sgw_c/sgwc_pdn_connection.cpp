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

/*! \file sgw_pdn_connection.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "sgwc_app.hpp"
#include "sgwc_eps_bearer_context.hpp"
#include "sgwc_config.hpp"

#include <algorithm>

using namespace oai::cn::core;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::sgwc;
using namespace std;

extern sgwc_app *sgwc_app_inst;

//------------------------------------------------------------------------------
fteid_t sgw_pdn_connection::generate_s5s8_up_fteid(const struct in_addr ipv4_address, const bearer_qos_t& bearer_qos) {
  fteid_t fteid = {};
  fteid.interface_type = S5_S8_SGW_GTP_U;
  fteid.v4 = 1;
  fteid.ipv4_address = ipv4_address;
  fteid.v6 = 0;
  fteid.ipv6_address = in6addr_any;
  for (auto it : sgw_eps_bearers) {
    if (it.second.get()->sgw_fteid_s5_s8_up.v4) {
      if (it.second.get()->eps_bearer_qos.is_arp_equals(bearer_qos)) {
        fteid.teid_gre_key = it.second.get()->sgw_fteid_s5_s8_up.teid_gre_key;
        return fteid;
      }
    }
  }
  fteid.teid_gre_key = sgwc_app_inst->generate_s5s8_up_teid();
  return fteid;
}
//------------------------------------------------------------------------------
void sgw_pdn_connection::add_eps_bearer(std::shared_ptr<sgw_eps_bearer> sb)
{
  if (sb.get()) {
    if ((sb.get()->ebi.ebi >= EPS_BEARER_IDENTITY_FIRST) and (sb.get()->ebi.ebi <= EPS_BEARER_IDENTITY_LAST)) {
      sgw_eps_bearers.insert(std::pair<uint8_t,std::shared_ptr<sgw_eps_bearer>>(sb.get()->ebi.ebi, sb));
      Logger::sgwc_app().trace( "sgw_pdn_connection::add_eps_bearer(%d) success", sb.get()->ebi.ebi);
    } else {
      Logger::sgwc_app().error( "sgw_pdn_connection::add_eps_bearer(%d) failed, invalid EBI", sb.get()->ebi.ebi);
    }
  }
}
//------------------------------------------------------------------------------
std::shared_ptr<sgw_eps_bearer> sgw_pdn_connection::get_eps_bearer(const core::ebi_t& ebi)
{
  if (sgw_eps_bearers.count(ebi.ebi)) {
    return sgw_eps_bearers.at(ebi.ebi);
  }
  return std::shared_ptr<sgw_eps_bearer>(nullptr);
}
//------------------------------------------------------------------------------
void sgw_pdn_connection::remove_eps_bearer(const core::ebi_t& ebi)
{
  std::shared_ptr<sgw_eps_bearer> sb = get_eps_bearer(ebi);
  if (sb.get()) {
    sb.get()->deallocate_ressources();
    sgw_eps_bearers.erase(ebi.ebi);
  }
}
//------------------------------------------------------------------------------
void sgw_pdn_connection::remove_eps_bearer(std::shared_ptr<sgw_eps_bearer> sb)
{
  if (sb.get()) {
    core::ebi_t ebi = {.ebi = sb.get()->ebi.ebi};
    sb.get()->deallocate_ressources();
    sgw_eps_bearers.erase(ebi.ebi);
  }
}
//------------------------------------------------------------------------------
void sgw_pdn_connection::delete_bearers()
{
  sgw_eps_bearers.clear();
}

//------------------------------------------------------------------------------
void sgw_pdn_connection::deallocate_ressources()
{
  Logger::sgwc_app().error( "TODO sgw_pdn_connection::deallocate_ressources()");
  for (auto it : sgw_eps_bearers) {
    it.second.get()->deallocate_ressources();
  }
}
//------------------------------------------------------------------------------
std::string sgw_pdn_connection::toString() const
{
  std::string s = {};
  s.reserve(300);
  s.append("PDN CONNECTION:\n");
  s.append("\tAPN IN USE:\t\t").append(apn_in_use).append("\n");
  s.append("\tPDN TYPE:\t\t").append(oai::cn::core::toString(pdn_type)).append("\n");
  s.append("\tPGW FTEID S5S8 CP:\t").append(oai::cn::core::toString(pgw_fteid_s5_s8_cp)).append("\n");
  //s.append("\tPGW ADDRESS IN USE UP:\t").append(oai::cn::core::toString(pgw_address_in_use_up)).append("\n");
  s.append("\tSGW FTEID S5S8 CP:\t").append(oai::cn::core::toString(sgw_fteid_s5_s8_cp)).append("\n");
  s.append("\tDEFAULT BEARER:\t\t").append(std::to_string(default_bearer.ebi)).append("\n");
  for (auto it : sgw_eps_bearers) {
    s.append(it.second.get()->toString());
  }
  return s;
}

