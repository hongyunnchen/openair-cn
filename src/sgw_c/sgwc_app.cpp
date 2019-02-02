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

/*! \file sgwc_app.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/
#include "conversions.hpp"
#include "itti.hpp"
#include "logger.hpp"
#if SGW_AUTOTEST
#include "mme_s11.hpp"
#endif
#include "sgwc_app.hpp"
#include "sgwc_config.hpp"
#include "sgwc_s5s8.hpp"
#include "sgwc_s11.hpp"

#include <stdexcept>

using namespace oai::cn::proto::gtpv2c;
using namespace oai::cn::proto::pfcp;
using namespace oai::cn::core;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::sgwc;
using namespace std;

// C includes

#if SGW_AUTOTEST
mme_s11   *mme_s11_inst = nullptr;
#endif
sgw_s11   *sgw_s11_inst = nullptr;
sgw_s5s8  *sgw_s5s8_inst = nullptr;

extern itti_mw *itti_inst;
extern sgwc_app *sgwc_app_inst;
extern sgwc_config sgwc_cfg;


void sgwc_app_task (void*);

//------------------------------------------------------------------------------
teid_t sgwc_app::generate_s11_cp_teid() {
  teid_t loop_detect_teid = teid_s11_cp;
  teid_t teid =  ++teid_s11_cp;
  while ((is_s11c_teid_exist(teid)) || (teid == UNASSIGNED_TEID)) {
    teid =  ++teid_s11_cp;
    if (loop_detect_teid == teid) return UNASSIGNED_TEID;
  }
  return teid;
}
//------------------------------------------------------------------------------
teid_t sgwc_app::generate_s5s8_cp_teid() {
  teid_t loop_detect_teid = teid_s5s8_cp;
  teid_t teid =  ++teid_s5s8_cp;
  while ((is_s5s8c_teid_exist(teid)) || (teid == UNASSIGNED_TEID)) {
    teid =  ++teid_s5s8_cp;
    if (loop_detect_teid == teid) return UNASSIGNED_TEID;
  }
  return teid;
}
//------------------------------------------------------------------------------
teid_t sgwc_app::generate_s5s8_up_teid() {
  teid_t teid =  ++teid_s5s8_up;
  while ((is_s5s8u_teid_exist(teid)) || (teid == UNASSIGNED_TEID)) {
    teid =  ++teid_s5s8_up;
  }
  return teid;
}
//------------------------------------------------------------------------------
bool sgwc_app::is_s11c_teid_exist(const teid_t& teid_s11_cp) const
{
  return bool{s11lteid2sgw_eps_bearer_context.count(teid_s11_cp) > 0};
}
//------------------------------------------------------------------------------
bool sgwc_app::is_s5s8c_teid_exist(const teid_t& teid_s5s8_cp) const
{
  return bool{s5s8lteid2sgw_contexts.count(teid_s5s8_cp) > 0};
}
//------------------------------------------------------------------------------
bool sgwc_app::is_s5s8u_teid_exist(const teid_t& teid_s5s8_up) const
{
  return bool{s5s8uplteid.count(teid_s5s8_up) > 0};
}
//------------------------------------------------------------------------------
fteid_t sgwc_app::generate_s11_cp_fteid(const struct in_addr ipv4_address) {
  fteid_t fteid = {};
  fteid.interface_type = S11_S4_SGW_GTP_C;
  fteid.v4 = 1;
  fteid.ipv4_address = ipv4_address;
  fteid.v6 = 0;
  fteid.ipv6_address = in6addr_any;
  fteid.teid_gre_key = generate_s11_cp_teid();
  return fteid;
}
//------------------------------------------------------------------------------
fteid_t sgwc_app::generate_s5s8_cp_fteid(const struct in_addr ipv4_address) {
  fteid_t fteid = {};
  fteid.interface_type = S5_S8_SGW_GTP_C;
  fteid.v4 = 1;
  fteid.ipv4_address = ipv4_address;
  fteid.v6 = 0;
  fteid.ipv6_address = in6addr_any;
  fteid.teid_gre_key = generate_s5s8_cp_teid();
  return fteid;
}
//------------------------------------------------------------------------------
bool sgwc_app::is_s5s8sgw_teid_2_sgw_contexts(const teid_t& sgw_teid) const
{
  return bool{s5s8lteid2sgw_contexts.count(sgw_teid) > 0};
}
//------------------------------------------------------------------------------
bool sgwc_app::is_s11sgw_teid_2_sgw_eps_bearer_context(const teid_t& sgw_teid) const
{
  return bool{s11lteid2sgw_eps_bearer_context.count(sgw_teid) > 0};
}
//------------------------------------------------------------------------------
std::pair<std::shared_ptr<sgw_eps_bearer_context>, std::shared_ptr<sgw_pdn_connection>> sgwc_app::s5s8sgw_teid_2_sgw_contexts(const teid_t& sgw_teid) const
{
  return s5s8lteid2sgw_contexts.at(sgw_teid);
}
//------------------------------------------------------------------------------
shared_ptr<sgw_eps_bearer_context> sgwc_app::s11sgw_teid_2_sgw_eps_bearer_context(const teid_t& sgw_teid) const
{
  return s11lteid2sgw_eps_bearer_context.at(sgw_teid);
}
//------------------------------------------------------------------------------
void sgwc_app::set_s5s8sgw_teid_2_sgw_contexts(const teid_t& sgw_teid, shared_ptr<sgw_eps_bearer_context> sebc, std::shared_ptr<sgw_pdn_connection> spc)
{
  s5s8lteid2sgw_contexts[sgw_teid] = std::make_pair(sebc, spc);
}
//------------------------------------------------------------------------------
void sgwc_app::set_s11sgw_teid_2_sgw_eps_bearer_context(const teid_t& sgw_teid, shared_ptr<sgw_eps_bearer_context> sebc)
{
  s11lteid2sgw_eps_bearer_context[sgw_teid] = sebc;
}
//------------------------------------------------------------------------------
bool sgwc_app::is_imsi64_2_sgw_eps_bearer_context(const imsi64_t& imsi64) const
{
  return bool{imsi2sgw_eps_bearer_context.count(imsi64) > 0};
}
//------------------------------------------------------------------------------
shared_ptr<sgw_eps_bearer_context> sgwc_app::imsi64_2_sgw_eps_bearer_context(const imsi64_t& imsi64) const
{
  return imsi2sgw_eps_bearer_context.at(imsi64);
}
//------------------------------------------------------------------------------
void sgwc_app::set_imsi64_2_sgw_eps_bearer_context(const imsi64_t& imsi64, shared_ptr<sgw_eps_bearer_context> sebc)
{
  imsi2sgw_eps_bearer_context[imsi64] = sebc;
}
//------------------------------------------------------------------------------
void sgwc_app::delete_sgw_eps_bearer_context(std::shared_ptr<sgw_eps_bearer_context> sebc)
{
  if (sebc.get()) {
    imsi64_t imsi64 = imsi_to_imsi64(&sebc.get()->imsi);
    Logger::sgwc_app().debug("Delete SGW EPS BEARER CONTEXT IMSI " IMSI_64_FMT "\n", imsi64);
    imsi2sgw_eps_bearer_context.erase(imsi64);
    s11lteid2sgw_eps_bearer_context.erase(sebc.get()->sgw_fteid_s11_s4_cp.teid_gre_key);
  }
}
//------------------------------------------------------------------------------
void sgwc_app_task (void *args_p)
{
  const task_id_t task_id = TASK_SGWC_APP;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {

    case S11_CREATE_SESSION_REQUEST:
        /*
         * We received a create session request from MME (with GTP abstraction here)
         * procedures might be:
         * E-UTRAN Initial Attach
         * UE requests PDN connectivity
         */
      if (itti_s11_create_session_request* m = dynamic_cast<itti_s11_create_session_request*>(msg)) {
        sgwc_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S5S8_CREATE_SESSION_RESPONSE:
      if (itti_s5s8_create_session_response* m = dynamic_cast<itti_s5s8_create_session_response*>(msg)) {
        sgwc_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S11_DELETE_SESSION_REQUEST:
      if (itti_s11_delete_session_request* m = dynamic_cast<itti_s11_delete_session_request*>(msg)) {
        sgwc_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S5S8_DELETE_SESSION_RESPONSE:
      if (itti_s5s8_delete_session_response* m = dynamic_cast<itti_s5s8_delete_session_response*>(msg)) {
        sgwc_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S11_MODIFY_BEARER_REQUEST:
      if (itti_s11_modify_bearer_request* m = dynamic_cast<itti_s11_modify_bearer_request*>(msg)) {
        sgwc_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S11_RELEASE_ACCESS_BEARERS_REQUEST:
      if (itti_s11_release_access_bearers_request* m = dynamic_cast<itti_s11_release_access_bearers_request*>(msg)) {
        sgwc_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case TIME_OUT:
      if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
        Logger::sgwc_app().info( "TIME-OUT event timer id %d", to->timer_id);
      }
      break;
    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::sgwc_app().info( "Received terminate message");
        return;
      }
      break;
    default:
      Logger::sgwc_app().info( "no handler for ITTI msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
sgwc_app::sgwc_app (const std::string& config_file) : s11lteid2sgw_eps_bearer_context()
{
  Logger::sgwc_app().startup("Starting...");
  sgwc_cfg.load(config_file);
  sgwc_cfg.execute();
  sgwc_cfg.display();

  teid_s11_cp = 0;
  teid_s5s8_cp = 0;
  teid_s5s8_up = 0;
  imsi2sgw_eps_bearer_context = {};
  s11lteid2sgw_eps_bearer_context = {};
  s5s8lteid2sgw_contexts = {};
  s5s8uplteid = {};

  try {
    sgw_s5s8_inst = new sgw_s5s8();
    sgw_s11_inst = new sgw_s11();
#if SGW_AUTOTEST
    mme_s11_inst = new mme_s11();
#endif
  } catch (std::exception& e) {
    Logger::sgwc_app().error( "Cannot create SGW_APP: %s", e.what() );
    throw e;
  }

  if (itti_inst->create_task(TASK_SGWC_APP, sgwc_app_task, nullptr) ) {
    Logger::sgwc_app().error( "Cannot create task TASK_SGWC_APP" );
    throw std::runtime_error( "Cannot create task TASK_SGWC_APP" );
  }

}

//------------------------------------------------------------------------------
sgwc_app::~sgwc_app()
{
  if (sgw_s5s8_inst) delete sgw_s5s8_inst;
  if (sgw_s11_inst) delete sgw_s11_inst;
#if SGW_AUTOTEST
  if (mme_s11_inst) delete mme_s11_inst;
#endif
}

//------------------------------------------------------------------------------
void sgwc_app::handle_itti_msg (itti_s11_create_session_request& csreq)
{
//  mme_sgw_tunnel_t                       *new_endpoint_p = NULL;
//  s_plus_p_gw_eps_bearer_context_information_t *s_plus_p_gw_eps_bearer_ctxt_info_p = NULL;
//  sgw_eps_bearer_ctxt_t                 *eps_bearer_ctxt_p = NULL;

  Logger::sgwc_app().debug("Received S11 CREATE_SESSION_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", csreq.teid, csreq.gtpc_tx_id);
  /*
   * Upon reception of create session request from MME,
   * S-GW should create UE, eNB and MME contexts and forward message to P-GW.
   */
  if (csreq.gtp_ies.rat_type.rat_type < RAT_TYPE_E_EUTRAN_WB_EUTRAN) {
    Logger::sgwc_app().warn("Received S11 CSReq with RAT < RAT_TYPE_E_EUTRAN_WB_EUTRAN: type %d\n", csreq.gtp_ies.rat_type.rat_type);
  }

  /*
   * As we are abstracting GTP-C transport, FTeid ip address is useless.
   *  We just use the teid to identify MME tunnel. Normally we received either:
   *  - ipv4 address if ipv4 flag is set
   *  - ipv6 address if ipv6 flag is set
   *  - ipv4 and ipv6 if both flags are set
   *  Communication between MME and S-GW involves S11 interface so we are expecting
   *  S11_MME_GTP_C (11) as interface_type.
   */
  if (csreq.gtp_ies.sender_fteid_for_cp.interface_type != S11_MME_GTP_C) {
    Logger::sgwc_app().warn("Received S11 CSReq with sender_fteid_for_cp != S11_MME_GTP_C %d, ignore CSreq\n", csreq.gtp_ies.sender_fteid_for_cp.interface_type);
    return;
  }
  if (csreq.gtp_ies.sender_fteid_for_cp.teid_gre_key == 0) {
    // MME sent request with teid = 0. This is not valid...
    Logger::sgwc_app().warn("Received S11 CSReq with sender_fteid_for_cp.teid = 0, ignore CSR\n");
    return;
  }

  if ((csreq.teid) && (not sgwc_app_inst->is_s11c_teid_exist(csreq.teid))) {
    Logger::sgwc_app().warn("Received S11 CSReq with dest teid " TEID_FMT " unknown, ignore CSreq\n", csreq.teid);
    return;
  }


  shared_ptr<sgw_eps_bearer_context> ebc;
  core::imsi_t imsi = {};
  if (csreq.gtp_ies.get(imsi)) {
    // imsi not authenticated
    core::indication_t indication = {};
    if ((csreq.gtp_ies.get(indication)) && (indication.uimsi)){
      Logger::sgwc_app().debug("TODO S11 CREATE_SESSION_REQUEST (no AUTHENTICATED IMSI) sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", csreq.teid, csreq.gtpc_tx_id);
      return;
    } else {
      imsi64_t imsi64 = imsi_to_imsi64(&imsi);
      if (is_imsi64_2_sgw_eps_bearer_context(imsi64)) {
        ebc = imsi64_2_sgw_eps_bearer_context(imsi64);
      } else {
        ebc = std::shared_ptr<sgw_eps_bearer_context>(new sgw_eps_bearer_context());
        set_imsi64_2_sgw_eps_bearer_context(imsi64, ebc);
      }
    }
  } else {
    if (csreq.teid) {
      if (is_s11sgw_teid_2_sgw_eps_bearer_context(csreq.teid)) {
        ebc = s11sgw_teid_2_sgw_eps_bearer_context(csreq.teid);
      } else {
        Logger::sgwc_app().debug("Discarding S11 CREATE_SESSION_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64", invalid teid\n", csreq.teid, csreq.gtpc_tx_id);
        return;
      }
    } else {
      // TODO
      Logger::sgwc_app().debug("TODO S11 CREATE_SESSION_REQUEST (no IMSI) sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", csreq.teid, csreq.gtpc_tx_id);
      return;
    }
  }
  ebc.get()->handle_itti_msg(csreq);
  Logger::sgwc_app().debug("sgw_eps_bearer_context: %s!", ebc.get()->toString().c_str());
}
//------------------------------------------------------------------------------
void sgwc_app::handle_itti_msg (itti_s11_delete_session_request& m)
{
  Logger::sgwc_app().debug("Received S11 DELETE_SESSION_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", m.teid, m.gtpc_tx_id);
  if (m.teid) {
    if (is_s11sgw_teid_2_sgw_eps_bearer_context(m.teid)) {
      shared_ptr<sgw_eps_bearer_context> ebc = s11sgw_teid_2_sgw_eps_bearer_context(m.teid);
      ebc.get()->handle_itti_msg(m);
      Logger::sgwc_app().debug("sgw_eps_bearer_context: %s!", ebc.get()->toString().c_str());
    } else {
      Logger::sgwc_app().debug("Discarding S11 CREATE_SESSION_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64", invalid teid\n", m.teid, m.gtpc_tx_id);
      return;
    }
  } else {
    // TODO
    Logger::sgwc_app().debug("Discarding S11 DELETE_SESSION_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", m.teid, m.gtpc_tx_id);
    return;
  }
}
//------------------------------------------------------------------------------
void sgwc_app::handle_itti_msg (itti_s11_modify_bearer_request& m)
{
  Logger::sgwc_app().debug("Received S11 MODIFY_BEARER_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", m.teid, m.gtpc_tx_id);
  if (m.teid) {
    if (is_s11sgw_teid_2_sgw_eps_bearer_context(m.teid)) {
      shared_ptr<sgw_eps_bearer_context> ebc = s11sgw_teid_2_sgw_eps_bearer_context(m.teid);
      ebc.get()->handle_itti_msg(m);
      Logger::sgwc_app().debug("sgw_eps_bearer_context: %s!", ebc.get()->toString().c_str());
    } else {
      Logger::sgwc_app().debug("Discarding S11 MODIFY_BEARER_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64", invalid teid\n", m.teid, m.gtpc_tx_id);
      return;
    }
  } else {
    // TODO
    Logger::sgwc_app().debug("Discarding S11 MODIFY_BEARER_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64", invalid teid\n", m.teid, m.gtpc_tx_id);
    return;
  }
}
//------------------------------------------------------------------------------
void sgwc_app::handle_itti_msg (itti_s11_release_access_bearers_request& m)
{
  Logger::sgwc_app().debug("Received S11 RELEASE_ACCESS_BEARERS_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", m.teid, m.gtpc_tx_id);
  Logger::sgwc_app().error("TODO rx itti_s11_release_access_bearers_request");
}
//------------------------------------------------------------------------------
void sgwc_app::handle_itti_msg (itti_s5s8_create_session_response& m)
{
  Logger::sgwc_app().debug("Received S5S8 CREATE_SESSION_RESPONSE sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", m.teid, m.gtpc_tx_id);
  if (m.gtp_ies.s5_s8_pgw_fteid.interface_type != S5_S8_PGW_GTP_C) {
    Logger::sgwc_app().warn("Received S5S8 CREATE_SESSION_RESPONSE with s5_s8_pgw_fteid.interface_type != S5_S8_PGW_GTP_C %d, ignore CSResp\n", m.gtp_ies.sender_fteid_for_cp.interface_type);
    return;
  }
  if (m.gtp_ies.s5_s8_pgw_fteid.teid_gre_key == 0) {
    // MME sent request with teid = 0. This is not valid...
    Logger::sgwc_app().warn("Received S5S8 CREATE_SESSION_RESPONSE with s5_s8_pgw_fteid.teid = 0, ignore CSResp\n");
    return;
  }
  if (is_s5s8sgw_teid_2_sgw_contexts(m.teid)) {
    std::pair<std::shared_ptr<sgw_eps_bearer_context>, std::shared_ptr<sgw_pdn_connection>> p = s5s8sgw_teid_2_sgw_contexts(m.teid);
    if ((p.first.get()) && (p.second.get())) {
      p.first.get()->handle_itti_msg(m, p.second);
      Logger::sgwc_app().debug("sgw_eps_bearer_context: %s!", p.first.get()->toString().c_str());
    } else {
      Logger::sgwc_app().debug("Received S5S8 CREATE_SESSION_RESPONSE with dest teid " TEID_FMT ", SGW contexts not found, ignore CSResp\n", m.teid);
    }
  } else {
    Logger::sgwc_app().debug("Received S5S8 CREATE_SESSION_RESPONSE with dest teid " TEID_FMT " unknown, ignore CSResp\n", m.teid);
  }
}
//------------------------------------------------------------------------------
void sgwc_app::handle_itti_msg (itti_s5s8_delete_session_response& m)
{
  if (is_s5s8sgw_teid_2_sgw_contexts(m.teid)) {
    std::pair<std::shared_ptr<sgw_eps_bearer_context>, std::shared_ptr<sgw_pdn_connection>> p = s5s8sgw_teid_2_sgw_contexts(m.teid);
    if ((p.first.get()) && (p.second.get())) {
      p.first.get()->handle_itti_msg(m, p.second);
      // cleanup
      if (0 == p.first.get()->get_num_pdn_connections()) {
        delete_sgw_eps_bearer_context(p.first);
      } else {
        Logger::sgwc_app().debug("get_num_pdn_connections() = %d\n", p.first.get()->get_num_pdn_connections());
      }
      Logger::sgwc_app().debug("sgw_eps_bearer_context: %s!", p.first.get()->toString().c_str());
    } else {
      Logger::sgwc_app().debug("Received S5S8 DELETE_SESSION_RESPONSE with dest teid " TEID_FMT ", SGW contexts not found, ignore DSResp\n", m.teid);
    }
  } else {
    Logger::sgwc_app().debug("Received S5S8 DELETE_SESSION_RESPONSE with dest teid " TEID_FMT " unknown, ignore DSResp\n", m.teid);
  }
}
//------------------------------------------------------------------------------
void sgwc_app::handle_itti_msg (itti_s5s8_modify_bearer_response& m)
{
  Logger::sgwc_app().debug("Received S5S8 MODIFY_BEARER_RESPONSE sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", m.teid, m.gtpc_tx_id);
  Logger::sgwc_app().error("TODO rx itti_s5s8_modify_bearer_response");
}

