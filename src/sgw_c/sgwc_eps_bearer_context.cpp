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

/*! \file sgw_eps_bearer_context.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "sgwc_app.hpp"
#include "sgwc_eps_bearer_context.hpp"
#include "sgwc_config.hpp"
#include "3gpp_29.274.h"

#include <algorithm>

using namespace oai::cn::core;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::sgwc;
using namespace std;

extern sgwc_app *sgwc_app_inst;
extern sgwc_config sgwc_cfg;

//------------------------------------------------------------------------------
std::string sgw_eps_bearer::toString() const
{
  std::string s = {};
  s.append("EPS BEARER:\n");
  s.append("\tEBI:\t\t\t\t").append(std::to_string(ebi.ebi)).append("\n");
  s.append("\tTFT:\t\t\t\tTODO tft").append("\n");
  s.append("\tPGW FTEID S5S8 UP:\t\t").append(oai::cn::core::toString(pgw_fteid_s5_s8_up)).append("\n");
  s.append("\tSGW FTEID S5S8 UP:\t\t").append(oai::cn::core::toString(sgw_fteid_s5_s8_up)).append("\n");
  s.append("\tSGW FTEID S1S12S4 UP:\t\t").append(oai::cn::core::toString(sgw_fteid_s1u_s12_s4u_s11u)).append("\n");
  s.append("\tSGW FTEID S11 UP:\t\t").append(oai::cn::core::toString(sgw_fteid_s11u)).append("\n");
  s.append("\tMME FTEID S11 UP:\t\t").append(oai::cn::core::toString(mme_fteid_s11u)).append("\n");
  s.append("\teNB FTEID S1 UP:\t\t").append(oai::cn::core::toString(enb_fteid_s1u)).append("\n");
  s.append("\tBearer QOS:\t\t\t").append(oai::cn::core::toString(eps_bearer_qos)).append("\n");
  return s;
}
//------------------------------------------------------------------------------
void sgw_eps_bearer::deallocate_ressources()
{
  Logger::sgwc_app().info( "TODO remove_eps_bearer(%d) OpenFlow", ebi.ebi);
  if (not is_fteid_zero(sgw_fteid_s5_s8_up))
    sgwc_app_inst->free_s5s8_up_fteid(sgw_fteid_s5_s8_up);
  //if (not is_fteid_zero(sgw_fteid_s1u_s12_s4u_s11u))
  //  sgwc_app_inst->free_s1s12s4s11_up_fteid(sgw_fteid_s1u_s12_s4u_s11u);
}

//------------------------------------------------------------------------------
void sgw_eps_bearer_context::erase_pdn_connection(std::shared_ptr<sgw_pdn_connection> spc)
{
  kpdn_t k = std::make_pair<std::string,uint8_t>(std::string(spc.get()->apn_in_use), (uint8_t)spc.get()->pdn_type.pdn_type);
  std::size_t size = pdn_connections.erase(k);
  Logger::sgwc_app().trace( "erase_pdn_connection(%s,%d) %d erased", spc.get()->apn_in_use.c_str(), spc.get()->pdn_type.pdn_type, size);
}

//------------------------------------------------------------------------------
shared_ptr<sgw_pdn_connection>  sgw_eps_bearer_context::insert_pdn_connection(sgw_pdn_connection* p)
{
  kpdn_t k(p->apn_in_use, (uint8_t)p->pdn_type.pdn_type);
  shared_ptr<sgw_pdn_connection> s = shared_ptr<sgw_pdn_connection>(p);
  std::pair<std::map<kpdn_t, shared_ptr<sgw_pdn_connection>>::iterator,bool> ret;
  ret = pdn_connections.insert(std::pair<kpdn_t, shared_ptr<sgw_pdn_connection>>(k, s));
  if (ret.second==false) {
    Logger::sgwc_app().error( "insert_pdn_connection(%s,%d) failed", ret.first->first.first.c_str(), (int)ret.first->first.second);
  } else {
    Logger::sgwc_app().trace( "insert_pdn_connection(%s,%d) succeed key(%s,%d)",
        ret.first->first.first.c_str(), (int)ret.first->first.second,k.first.c_str(), (int)k.second);
  }
  return s;
}
//------------------------------------------------------------------------------
shared_ptr<sgw_pdn_connection> sgw_eps_bearer_context::find_pdn_connection(const std::string apn, const pdn_type_t pdn_type)
{
  kpdn_t k(apn, pdn_type.pdn_type);
  std::map<kpdn_t,shared_ptr<sgw_pdn_connection>>::iterator it;

  it = pdn_connections.find(k);
  if (it != pdn_connections.end())
    return it->second;

  return shared_ptr<sgw_pdn_connection>(nullptr);
  // same return nullptr;

}
//------------------------------------------------------------------------------
std::shared_ptr<sgw_pdn_connection> sgw_eps_bearer_context::find_pdn_connection(const core::ebi_t& ebi)
{
  for (auto it=pdn_connections.begin(); it!=pdn_connections.end(); ++it) {
    if (it->second.get()->default_bearer.ebi == ebi.ebi) {
      return it->second;
    }
    std::shared_ptr<sgw_eps_bearer> seb = it->second.get()->get_eps_bearer(ebi);
    if (seb.get()) {
      return it->second;
    }
  }
  return shared_ptr<sgw_pdn_connection>(nullptr);
}

//------------------------------------------------------------------------------
void sgw_eps_bearer_context::create_procedure(itti_s11_create_session_request& csreq)
{
  create_session_request_procedure* p = new create_session_request_procedure(csreq);
  insert_procedure(p);
  if (p->run(sgwc_app_inst->s11sgw_teid_2_sgw_eps_bearer_context(this->sgw_fteid_s11_s4_cp.teid_gre_key))) {
    // TODO handle error code
    Logger::sgwc_app().info( "S11 CREATE_SESSION_REQUEST procedure failed");
    remove_procedure(p);
  } else {
  }
}
//------------------------------------------------------------------------------
void sgw_eps_bearer_context::create_procedure(itti_s11_modify_bearer_request& mbreq)
{
  //Assuming actually that only one pdn_connection per modify bearer request
  if (mbreq.gtp_ies.has_bearer_context_to_be_modified() || mbreq.gtp_ies.has_bearer_context_to_be_removed()) {
    modify_bearer_request_procedure* p = new modify_bearer_request_procedure(mbreq);
    insert_procedure(p);
    if (p->run(sgwc_app_inst->s11sgw_teid_2_sgw_eps_bearer_context(this->sgw_fteid_s11_s4_cp.teid_gre_key))) {
      // TODO handle error code
      Logger::sgwc_app().info( "S11 MODIFY_BEARER_REQUEST procedure failed");
      remove_procedure(p);
    } else {
    }
  } else {
    Logger::sgwc_app().error("S11 MODIFY_BEARER_REQUEST not bearer context to be modified or to be removed found, should be handled by GTPV2-C stack, silently discarded!");
  }
}
//------------------------------------------------------------------------------
void sgw_eps_bearer_context::create_procedure(itti_s11_delete_session_request& dsreq)
{
  std::vector<shared_ptr<sgw_pdn_connection>> to_delete = {}; // list of PDN connections to delete
  core::ebi_t default_bearer = {};
  if (dsreq.gtp_ies.get(default_bearer)) {
    shared_ptr<sgw_pdn_connection> pdn = find_pdn_connection(default_bearer);
    if (pdn.get()) {
      to_delete.push_back(pdn);
    } else {
      // TODO return error
      Logger::sgwc_app().info("S11 DELETE_SESSION_REQUEST PDN connection not found, discarded!");
    }
  } else {
    // Normally should be only one PDN connection
    // TODO decide what todo (reject request, delete all, ?)
    for (auto it=pdn_connections.begin(); it!=pdn_connections.end(); ++it) {
      to_delete.push_back(it->second);
    }
  }

  for (auto it=to_delete.begin(); it!=to_delete.end(); ++it) {
    delete_session_request_procedure* p = new delete_session_request_procedure(dsreq, *it);
    insert_procedure(p);
    if (p->run(shared_from_this())) {
      Logger::sgwc_app().info( "S11 DELETE_SESSION_REQUEST procedure failed");
      // TODO handle error code
      remove_procedure(p);
    }
  }
}
//------------------------------------------------------------------------------
void sgw_eps_bearer_context::insert_procedure(sebc_procedure* proc)
{
  pending_procedures.push_back(shared_ptr<sebc_procedure>(proc));
}
//------------------------------------------------------------------------------
shared_ptr<sebc_procedure> sgw_eps_bearer_context::find_procedure(const uint64_t& gtpc_tx_id)
{
  auto found = std::find_if(pending_procedures.begin(), pending_procedures.end(), [gtpc_tx_id](std::shared_ptr<sebc_procedure> const& i) -> bool { return i.get()->gtpc_tx_id == gtpc_tx_id;});
  if (found != pending_procedures.end()) {
    return *found;
  }
  return shared_ptr<sebc_procedure>(nullptr);
}
//------------------------------------------------------------------------------
void sgw_eps_bearer_context::remove_procedure(sebc_procedure* proc)
{
  auto found = std::find_if(pending_procedures.begin(), pending_procedures.end(), [proc](std::shared_ptr<sebc_procedure> const& i) {
    return i.get() == proc;
  });
  if (found != pending_procedures.end()) {
    pending_procedures.erase(found);
  }
}
//------------------------------------------------------------------------------
void sgw_eps_bearer_context::delete_pdn_connection(std::shared_ptr<sgw_pdn_connection> spc)
{
  if (spc.get()) {
    Logger::sgwc_app().debug("sgw_eps_bearer_context::delete_pdn_connection() OK doing it");
    erase_pdn_connection(spc);
    spc.get()->deallocate_ressources();
    spc.get()->delete_bearers();
  }
}

//------------------------------------------------------------------------------
void sgw_eps_bearer_context::handle_itti_msg (itti_s11_create_session_request& csreq)
{
  if (sgw_fteid_s11_s4_cp.teid_gre_key == UNASSIGNED_TEID) {
    sgw_fteid_s11_s4_cp = sgwc_app_inst->generate_s11_cp_fteid(sgwc_cfg.s11_cp.addr4);
    sgwc_app_inst->set_s11sgw_teid_2_sgw_eps_bearer_context(sgw_fteid_s11_s4_cp.teid_gre_key, shared_from_this());
    mme_fteid_s11 = csreq.gtp_ies.sender_fteid_for_cp;
    imsi = csreq.gtp_ies.imsi;
  } else {
    if (not is_fteid_equal(mme_fteid_s11, csreq.gtp_ies.sender_fteid_for_cp)) {
      Logger::sgwc_app().debug("S11 CREATE_SESSION_REQUEST MME S11 FTEID changed");
      mme_fteid_s11 = csreq.gtp_ies.sender_fteid_for_cp;
    }
  }
  create_procedure(csreq);
}
//------------------------------------------------------------------------------
void sgw_eps_bearer_context::handle_itti_msg (itti_s11_modify_bearer_request& mbreq)
{
  shared_ptr<sebc_procedure> sp = find_procedure(mbreq.gtpc_tx_id);
  if (sp.get()) {
    Logger::sgwc_app().error("S11 MODIFY_BEARER_REQUEST ignored, existing procedure found gtpc_tx_id %d!", mbreq.gtpc_tx_id);
    return;
  } else {
    create_procedure(mbreq);
  }
}
//------------------------------------------------------------------------------
void sgw_eps_bearer_context::handle_itti_msg (itti_s11_delete_session_request& dsreq)
{
  shared_ptr<sebc_procedure> sp = find_procedure(dsreq.gtpc_tx_id);
  if (sp.get()) {
    Logger::sgwc_app().error("S11 DELETE_SESSION_REQUEST ignored, existing procedure found gtpc_tx_id %d!", dsreq.gtpc_tx_id);
    return;
  } else {
    core::indication_t indication = {};
    if (dsreq.gtp_ies.get(indication)) {
      if (indication.oi) {
        create_procedure(dsreq);
        return;
      }
    } else {
      Logger::sgwc_app().trace("S11 DELETE_SESSION_REQUEST indication.u1.b = %d");
    }
    // TODO DELETE SESSION locally
    Logger::sgwc_app().info("S11 DELETE_SESSION_REQUEST TODO delete session locally");
  }
}

//------------------------------------------------------------------------------
void sgw_eps_bearer_context::handle_itti_msg (itti_s5s8_create_session_response& csresp, std::shared_ptr<sgw_pdn_connection> spc)
{
  shared_ptr<sebc_procedure> sp = find_procedure(csresp.gtpc_tx_id);
  if (sp.get()) {
    sp.get()->handle_itti_msg(csresp, shared_from_this(), spc);
    remove_procedure(sp.get());
  } else {
    Logger::sgwc_app().debug("S5S8 CREATE_SESSION_RESPONSE ignored, no procedure found gtpc_tx_id %d!", csresp.gtpc_tx_id);
  }
}
//------------------------------------------------------------------------------
void sgw_eps_bearer_context::handle_itti_msg (itti_s5s8_delete_session_response& dsresp, std::shared_ptr<sgw_pdn_connection> spc)
{
  shared_ptr<sebc_procedure> sp = find_procedure(dsresp.gtpc_tx_id);
  if (sp.get()) {
    sp.get()->handle_itti_msg(dsresp, shared_from_this(), spc);
    remove_procedure(sp.get());
  } else {
    Logger::sgwc_app().debug("S5S8 CREATE_SESSION_RESPONSE ignored, no procedure found gtpc_tx_id %d!", dsresp.gtpc_tx_id);
  }
}
//------------------------------------------------------------------------------
std::string sgw_eps_bearer_context::toString() const
{
  std::string s = {};
  s.append("SGW EPS BEARER CONTEXT:\n");
  s.append("\tIMSI:\t\t\t").append(oai::cn::core::toString(imsi)).append("\n");
  s.append("\tIMSI UNAUTHENTICATED:\t").append(std::to_string(imsi_unauthenticated_indicator)).append("\n");
  s.append("\tMME FTEID S11 CP:\t").append(oai::cn::core::toString(mme_fteid_s11)).append("\n");
  s.append("\tSGW FTEID S11 CP:\t").append(oai::cn::core::toString(sgw_fteid_s11_s4_cp)).append("\n");
  //s.append("\tSGSN FTEID S4 CP:\t").append(oai::cn::core::toString(sgsn_fteid_s4_cp)).append("\n");
  s.append("\tLAST KNOWN CELL ID:\t").append(oai::cn::core::toString(last_known_cell_Id)).append("\n");
  for (auto it : pdn_connections) {
    s.append(it.second.get()->toString());
  }
  return s;
}

