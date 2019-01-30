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

/*! \file pgw_app.cpp
   \brief
   \author  Lionel GAUTHIER
   \date 2018
   \email: lionel.gauthier@eurecom.fr
*/
#include "async_shell_cmd.hpp"
#include "common_defs.h"
#include "conversions.h"

#include "itti.hpp"
#include "logger.hpp"
#include "pgw_app.hpp"
#include "pgw_config.hpp"
#include "pgw_s5s8.hpp"
#include "string.hpp"

#include <stdexcept>

using namespace oai::cn::core;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::pgwc;
using namespace oai::cn::util;
using namespace std;

pgw_s5s8  *pgw_s5s8_inst = nullptr;

#define SYSTEM_CMD_MAX_STR_SIZE 512
extern async_shell_cmd *async_shell_cmd_inst;
extern pgw_app *pgw_app_inst;
extern pgw_config pgw_cfg;
extern itti_mw *itti_inst;

void pgw_app_task (void*);

//------------------------------------------------------------------------------
int pgw_app::apply_config (const pgw_config& cfg)
{
  Logger::pgwc_app().info("Apply config...");
  struct in_addr                          addr_cur;

#if ENABLE_LIBGTPNL
  async_shell_cmd_inst->run_command(TASK_PGWC_APP, PGW_ABORT_ON_ERROR, __FILE__, __LINE__, std::string("iptables -t mangle -F OUTPUT"));
  async_shell_cmd_inst->run_command(TASK_PGWC_APP, PGW_ABORT_ON_ERROR, __FILE__, __LINE__, std::string("(iptables -t mangle -F POSTROUTING"));

  if (config_pP->masquerade_SGI) {
    async_shell_cmd_inst->run_command(TASK_PGWC_APP, PGW_ABORT_ON_ERROR, __FILE__, __LINE__, std::string("iptables -t nat -F PREROUTING"));
  }
#endif

  num_ue_pool = cfg.num_ue_pool;

  for (int i = 0; i < num_ue_pool; i++) {
    //Any math should be applied onto host byte order i.e. ntohl()
    addr_cur.s_addr = cfg.ue_pool_range_low[i].s_addr;
    while (htonl(addr_cur.s_addr) <=  htonl(cfg.ue_pool_range_high[i].s_addr)) {
      this->ipv4_pool_list[i].push_back(addr_cur);

      if (cfg.arp_ue_linux) {
#if ENABLE_LIBGTPNL
        async_shell_cmd_inst->run_command(TASK_PGWC_APP, PGW_ABORT_ON_ERROR, __FILE__, __LINE__, string_format("arp -nDs %s %s pub", inet_ntoa(addr_cur), cfg.ipv4.if_name_SGI.c_str()));

#else
#if ENABLE_OPENFLOW
        async_shell_cmd_inst->run_command(TASK_PGWC_APP, PGW_ABORT_ON_ERROR, __FILE__, __LINE__, string_format("arp -nDs %s %s pub", inet_ntoa(addr_cur), cfg.ovs_config.bridge_name.c_str()));
#endif
#endif
      }
      addr_cur.s_addr = htonl( ntohl(addr_cur.s_addr) + 1 );
    }
    //---------------
#if ENABLE_LIBGTPNL

    uint32_t min_mtu = cfg.ipv4.mtu_SGI;
    // 36 = GTPv1-U min header size
    if ((cfg.ipv4.mtu_S5_S8 - 36) < min_mtu) {
      min_mtu = cfg.ipv4.mtu_S5_S8 - 36;
    }

    if (cfg.masquerade_SGI) {
      async_shell_cmd_inst->run_command(TASK_PGWC_APP, PGW_ABORT_ON_ERROR, __FILE__, __LINE__, string_format("iptables -t nat -I POSTROUTING -m iprange --src-range %s-%s -o %s  ! --protocol sctp -j SNAT --to-source %s",
          inet_ntoa(cfg.ue_pool_range_low[i]), inet_ntoa(cfg.ue_pool_range_high[i]),
          cfg.ipv4.if_name_SGI.c_str(), str_sgi));
      }

    if (cfg.ue_tcp_mss_clamp) {
      async_shell_cmd_inst->run_command(TASK_PGWC_APP, PGW_ABORT_ON_ERROR, __FILE__, __LINE__, string_format("iptables -t mangle -I FORWARD -m iprange --src-range %s-%s   -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %u",
          inet_ntoa(cfg.ue_pool_range_low[i]), inet_ntoa(cfg.ue_pool_range_high[i]), min_mtu - 40));

      async_shell_cmd_inst->run_command(TASK_PGWC_APP, PGW_ABORT_ON_ERROR, __FILE__, __LINE__, string_format("iptables -t mangle -I FORWARD -m iprange --dst-range %s-%s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %u",
          inet_ntoa(cfg.ue_pool_range_low[i]), inet_ntoa(cfg.ue_pool_range_high[i]), min_mtu - 40));
    }
#endif
  }
#if ENABLE_LIBGTPNL
  if (cfg.pcef.tcp_ecn_enabled) {
    async_shell_cmd_inst->run_command(TASK_PGWC_APP, PGW_ABORT_ON_ERROR, __FILE__, __LINE__, std::string("sysctl -w net.ipv4.tcp_ecn=1"));
  }
#endif
  Logger::pgwc_app().info("Applied config");
  return RETURNok;
}

//------------------------------------------------------------------------------
teid_t pgw_app::generate_s5s8_cp_teid() {
  teid_t teid =  ++teid_s5s8_cp;
  while ((is_s5s8c_teid_exist(teid)) || (teid == UNASSIGNED_TEID)) {
    teid =  ++teid_s5s8_cp;
  }
  s5s8cplteid.insert(teid);
  return teid;
}
//------------------------------------------------------------------------------
teid_t pgw_app::generate_s5s8_up_teid() {
  teid_t teid =  ++teid_s5s8_up;
  while ((is_s5s8u_teid_exist(teid)) || (teid == UNASSIGNED_TEID)) {
    teid =  ++teid_s5s8_up;
  }
  s5s8uplteid.insert(teid);
  return teid;
}
//------------------------------------------------------------------------------
bool pgw_app::is_s5s8c_teid_exist(teid_t& teid_s5s8_cp)
{
  return bool{s5s8cplteid.count(teid_s5s8_cp) > 0};
}
//------------------------------------------------------------------------------
bool pgw_app::is_s5s8u_teid_exist(teid_t& teid_s5s8_up)
{
  return bool{s5s8uplteid.count(teid_s5s8_up) > 0};
}
//------------------------------------------------------------------------------
void pgw_app::free_s5s8c_teid(const teid_t& teid_s5s8_cp)
{
  s5s8cplteid.erase (teid_s5s8_cp); // can return value of erase
}
//------------------------------------------------------------------------------
void pgw_app::free_s5s8u_teid(const teid_t& teid_s5s8_up)
{
  s5s8uplteid.erase (teid_s5s8_up); // can return value of erase
}
//------------------------------------------------------------------------------
bool pgw_app::is_imsi64_2_pgw_context(const imsi64_t& imsi64) const
{
  return bool{imsi2pgw_context.count(imsi64) > 0};
}
//------------------------------------------------------------------------------
shared_ptr<pgw_context> pgw_app::imsi64_2_pgw_context(const imsi64_t& imsi64) const
{
  return imsi2pgw_context.at(imsi64);
}
//------------------------------------------------------------------------------
void pgw_app::set_imsi64_2_pgw_context(const imsi64_t& imsi64, shared_ptr<pgw_context> pc)
{
  imsi2pgw_context[imsi64] = pc;
}
//------------------------------------------------------------------------------
fteid_t pgw_app::build_s5s8_cp_fteid(const struct in_addr ipv4_address, const teid_t teid)
{
  fteid_t fteid = {};
  fteid.interface_type = S5_S8_PGW_GTP_C;
  fteid.v4 = 1;
  fteid.ipv4_address = ipv4_address;
  fteid.v6 = 0;
  fteid.ipv6_address = in6addr_any;
  fteid.teid_gre_key = teid;
  return fteid;
}
//------------------------------------------------------------------------------
fteid_t pgw_app::build_s5s8_up_fteid(const struct in_addr ipv4_address, const teid_t teid)
{
  fteid_t fteid = {};
  fteid.interface_type = S5_S8_PGW_GTP_U;
  fteid.v4 = 1;
  fteid.ipv4_address = ipv4_address;
  fteid.v6 = 0;
  fteid.ipv6_address = in6addr_any;
  fteid.teid_gre_key = teid;
  return fteid;
}
//------------------------------------------------------------------------------
fteid_t pgw_app::generate_s5s8_cp_fteid(const struct in_addr ipv4_address)
{
  teid_t teid = generate_s5s8_cp_teid();
  return build_s5s8_cp_fteid(ipv4_address, teid);
}
//------------------------------------------------------------------------------
void  pgw_app::free_s5s8_cp_fteid(const core::fteid_t& fteid)
{
  s5s8lteid2pgw_context.erase(fteid.teid_gre_key);
  free_s5s8c_teid(fteid.teid_gre_key);
}
//------------------------------------------------------------------------------
fteid_t pgw_app::generate_s5s8_up_fteid(const struct in_addr ipv4_address)
{
  teid_t teid = generate_s5s8_up_teid();
  return build_s5s8_up_fteid(ipv4_address, teid);
}
//------------------------------------------------------------------------------
void  pgw_app::free_s5s8_up_fteid(const core::fteid_t& fteid)
{
  free_s5s8u_teid(fteid.teid_gre_key);
}

//------------------------------------------------------------------------------
bool pgw_app::is_s5s8cpgw_fteid_2_pgw_context(fteid_t& ls5s8_fteid)
{
  return bool{s5s8lteid2pgw_context.count(ls5s8_fteid.teid_gre_key) > 0};
}
//------------------------------------------------------------------------------
shared_ptr<pgw_context> pgw_app::s5s8cpgw_fteid_2_pgw_context(fteid_t& ls5s8_fteid)
{
  if (is_s5s8cpgw_fteid_2_pgw_context(ls5s8_fteid)) {
    return s5s8lteid2pgw_context.at(ls5s8_fteid.teid_gre_key);
  } else {
    return shared_ptr<pgw_context>(nullptr);
  }

}
//------------------------------------------------------------------------------
void pgw_app::set_s5s8cpgw_fteid_2_pgw_context(fteid_t& ls5s8_fteid, shared_ptr<pgw_context> spc)
{
  s5s8lteid2pgw_context[ls5s8_fteid.teid_gre_key] = spc;
}

//------------------------------------------------------------------------------
void pgw_app::delete_pgw_context(shared_ptr<pgw_context> spc)
{
  core::imsi_t imsi = {};
  imsi = spc.get()->imsi;
  imsi64_t imsi64 = imsi_to_imsi64(&imsi);
  imsi2pgw_context.erase(imsi64);
}

//------------------------------------------------------------------------------
void pgw_app_task (void*)
{
  const task_id_t task_id = TASK_PGWC_APP;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {


    case GTPV1U_CREATE_TUNNEL_RESP:
//      if (itti_msg_gtpv1u_create_tunnel_resp* m = dynamic_cast<itti_msg_gtpv1u_create_tunnel_resp*>(msg)) {
//        Logger::pgwc_app().info("Received teid for S1-U: %u and status: %s\n", GTPV1U_CREATE_TUNNEL_RESP(received_message_p)->S1u_teid, GTPV1U_CREATE_TUNNEL_RESP(received_message_p)->status == 0 ? "Success" : "Failure");
//        sgw_handle_gtpv1uCreateTunnelResp (m);
//      }
      break;

    case GTPV1U_UPDATE_TUNNEL_RESP:
//      if (itti_msg_gtpv1u_update_tunnel_resp* m = dynamic_cast<itti_msg_gtpv1u_update_tunnel_resp*>(msg)) {
//        sgw_handle_gtpv1uUpdateTunnelResp (m);
//      }
      break;

    case S5S8_CREATE_SESSION_REQUEST:
      if (itti_s5s8_create_session_request* m = dynamic_cast<itti_s5s8_create_session_request*>(msg)) {
        pgw_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S5S8_DELETE_SESSION_REQUEST:
      if (itti_s5s8_delete_session_request* m = dynamic_cast<itti_s5s8_delete_session_request*>(msg)) {
        pgw_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S5S8_MODIFY_BEARER_REQUEST:
      if (itti_s5s8_modify_bearer_request* m = dynamic_cast<itti_s5s8_modify_bearer_request*>(msg)) {
        pgw_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case TIME_OUT:
      if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
        Logger::pgwc_app().info( "TIME-OUT event timer id %d", to->timer_id);
      }
      break;
    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::pgwc_app().info( "Received terminate message");
        return;
      }
      break;
    default:
      Logger::sgwc_app().info( "no handler for msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
pgw_app::pgw_app (const std::string& config_file)
{
  Logger::pgwc_app().startup("Starting...");

  teid_s5s8_cp = 0;
  teid_s5s8_up = 0;
  imsi2pgw_context = {};
  s5s8lteid2pgw_context = {};
  s5s8cplteid = {};
  s5s8uplteid = {};
  num_ue_pool = 0;
  for (int i = 0; i < PGW_NUM_UE_POOL_MAX; i++) {
    ipv4_pool_list[i] = {};
  }

  pgw_cfg.load(config_file);
  pgw_cfg.display();
  apply_config (pgw_cfg);

  //  if ( gtpv1u_init (spgw_config_pP) < 0) {
  //    OAILOG_ALERT (LOG_SPGW_APP, "Initializing GTPv1-U ERROR\n");
  //    return RETURNerror;
  //  }
  //  pgw_ip_address_pool_init ();


  if (itti_inst->create_task(TASK_PGWC_APP, pgw_app_task, nullptr) ) {
    Logger::pgwc_app().error( "Cannot create task TASK_PGWC_APP" );
    throw std::runtime_error( "Cannot create task TASK_PGWC_APP" );
  }

  try {
    pgw_s5s8_inst = new pgw_s5s8();
  } catch (std::exception& e) {
    Logger::pgwc_app().error( "Cannot create PGW_APP: %s", e.what() );
    throw e;
  }

  Logger::pgwc_app().startup( "Started" );
}

//------------------------------------------------------------------------------
void pgw_app::send_delete_session_response_cause_request_accepted (const uint64_t gtpc_tx_id, const teid_t teid, boost::asio::ip::udp::endpoint& r_endpoint) const
{
  core::cause_t            cause = {.cause_value = REQUEST_ACCEPTED, .pce = 0, .bce = 0, .cs = 0};
  itti_s5s8_delete_session_response *s5s8_dsr = new itti_s5s8_delete_session_response(TASK_PGWC_APP, TASK_PGWC_S5S8);
  //------
  // GTPV2C-Stack
  //------
  s5s8_dsr->gtpc_tx_id = gtpc_tx_id;
  s5s8_dsr->teid = teid;
  s5s8_dsr->r_endpoint = r_endpoint;
  s5s8_dsr->gtp_ies.set(cause);
  std::shared_ptr<itti_s5s8_delete_session_response> msg = std::shared_ptr<itti_s5s8_delete_session_response>(s5s8_dsr);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::pgwc_app().error( "Could not send ITTI message %s to task TASK_PGWC_S5S8", s5s8_dsr->get_msg_name());
  }

}
//------------------------------------------------------------------------------
void pgw_app::send_delete_session_response_cause_context_not_found (const uint64_t gtpc_tx_id, const teid_t teid, boost::asio::ip::udp::endpoint& r_endpoint) const
{
  core::cause_t            cause = {.cause_value = CONTEXT_NOT_FOUND, .pce = 0, .bce = 0, .cs = 0};
  itti_s5s8_delete_session_response *s5s8_dsr = new itti_s5s8_delete_session_response(TASK_PGWC_APP, TASK_PGWC_S5S8);
  //------
  // GTPV2C-Stack
  //------
  s5s8_dsr->gtpc_tx_id = gtpc_tx_id;
  s5s8_dsr->teid = teid;
  s5s8_dsr->r_endpoint = r_endpoint;
  s5s8_dsr->gtp_ies.set(cause);
  std::shared_ptr<itti_s5s8_delete_session_response> msg = std::shared_ptr<itti_s5s8_delete_session_response>(s5s8_dsr);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::pgwc_app().error( "Could not send ITTI message %s to task TASK_PGWC_S5S8", s5s8_dsr->get_msg_name());
  }

}
//------------------------------------------------------------------------------
void pgw_app::handle_itti_msg (itti_s5s8_create_session_request& csreq)
{
  Logger::pgwc_app().debug("Received S5S8 CREATE_SESSION_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", csreq.teid, csreq.gtpc_tx_id);

  if (csreq.gtp_ies.rat_type.rat_type < RAT_TYPE_E_EUTRAN_WB_EUTRAN) {
    Logger::pgwc_app().warn("Received S5_S8 CREATE_SESSION_REQUEST with RAT != RAT_TYPE_E_EUTRAN_WB_EUTRAN: type %d", csreq.gtp_ies.rat_type);
  }

  if (csreq.gtp_ies.sender_fteid_for_cp.interface_type != S5_S8_SGW_GTP_C) {
    Logger::pgwc_app().warn("Received S5_S8 CREATE_SESSION_REQUEST with sender_fteid_for_cp != S5_S8_SGW_GTP_C %d, ignore message", csreq.gtp_ies.sender_fteid_for_cp.interface_type);
    return;
  }
  if (csreq.gtp_ies.sender_fteid_for_cp.teid_gre_key == 0) {
    // MME sent request with teid = 0. This is not valid...
    Logger::pgwc_app().warn("Received S5_S8 CREATE_SESSION_REQUEST with sender_fteid_for_cp.teid = 0, ignore message");
    return;
  }
  if ((csreq.teid) && (not pgw_app_inst->is_s5s8c_teid_exist(csreq.teid))) {
    Logger::sgwc_app().warn("Received S5_S8 CREATE_SESSION_REQUEST with dest teid " TEID_FMT " unknown, ignore message\n", csreq.teid);
    return;
  }

  if (not pgw_cfg.is_apn_handled(csreq.gtp_ies.apn.access_point_name, csreq.gtp_ies.pdn_type)) {
    // MME sent request with teid = 0. This is not valid...
    Logger::pgwc_app().warn("Received CREATE_SESSION_REQUEST unknown requested APN %s, ignore message", csreq.gtp_ies.apn.access_point_name.c_str());
    // TODO send reply
    return;
  }


  shared_ptr<pgw_context> pc;
  core::imsi_t imsi = {};
  if (csreq.gtp_ies.get(imsi)) {
    // imsi not authenticated
    core::indication_t indication = {};
    if ((csreq.gtp_ies.get(indication)) && (indication.uimsi)){
      Logger::pgwc_app().debug("TODO S5_S8 CREATE_SESSION_REQUEST (no AUTHENTICATED IMSI) sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", csreq.teid, csreq.gtpc_tx_id);
      return;
    } else {
      imsi64_t imsi64 = imsi_to_imsi64(&imsi);
      if (is_imsi64_2_pgw_context(imsi64)) {
        pc = imsi64_2_pgw_context(imsi64);
      } else {
        pc = std::shared_ptr<pgw_context>(new pgw_context());
        set_imsi64_2_pgw_context(imsi64, pc);
      }
    }
  } else {
    if (csreq.teid) {
      core::fteid_t l_fteid = pgw_app_inst->build_s5s8_cp_fteid(pgw_cfg.s5s8_cp.addr4, csreq.teid);
      if (is_s5s8c_teid_exist(csreq.teid)) {
        pc = s5s8cpgw_fteid_2_pgw_context(l_fteid);
      } else {
        Logger::pgwc_app().debug("Discarding S5_S8 CREATE_SESSION_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64", invalid teid\n", csreq.teid, csreq.gtpc_tx_id);
        return;
      }
    } else {
      // TODO
      Logger::pgwc_app().debug("TODO S5_S8 CREATE_SESSION_REQUEST (no IMSI) sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", csreq.teid, csreq.gtpc_tx_id);
      return;
    }
  }
  pc.get()->handle_itti_msg(csreq);
}
//------------------------------------------------------------------------------
void pgw_app::handle_itti_msg (itti_s5s8_delete_session_request& dsreq)
{
  Logger::pgwc_app().debug("Received S5S8 DELETE_SESSION_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", dsreq.teid, dsreq.gtpc_tx_id);

  core::fteid_t sender_fteid = {};
  bool sender_fteid_present = dsreq.gtp_ies.get(sender_fteid);

  if (sender_fteid_present) {
    if (dsreq.gtp_ies.sender_fteid_for_cp.interface_type != S5_S8_SGW_GTP_C) {
      Logger::pgwc_app().warn("Received S5_S8 DELETE_SESSION_REQUEST with sender_fteid_for_cp != S5_S8_SGW_GTP_C %d, ignore message", dsreq.gtp_ies.sender_fteid_for_cp.interface_type);
      return;
    }
    // Should be handled by gtpv2-c layer
    if (dsreq.gtp_ies.sender_fteid_for_cp.teid_gre_key == 0) {
      // MME sent request with teid = 0. This is not valid...
      Logger::pgwc_app().warn("Received S5_S8 DELETE_SESSION_REQUEST with sender_fteid_for_cp.teid = 0, ignore message");
      return;
    }
  }
  core::fteid_t l_fteid = build_s5s8_cp_fteid(pgw_cfg.s5s8_cp.addr4, dsreq.teid);
  shared_ptr<pgw_context> pc = s5s8cpgw_fteid_2_pgw_context(l_fteid);
  if (pc.get()) {
    pc.get()->handle_itti_msg(dsreq);
    if (0 == pc.get()->get_num_apn_contexts()) {
      delete_pgw_context(pc);
    }
  } else {
    if (sender_fteid_present) {
      Logger::sgwc_app().info("Received S5_S8 DELETE_SESSION_REQUEST with dest teid " TEID_FMT " unknown, notify sender\n", dsreq.teid);
      send_delete_session_response_cause_context_not_found (dsreq.gtpc_tx_id, sender_fteid.teid_gre_key, dsreq.r_endpoint);
      return;
    } else {
      Logger::sgwc_app().info("Received S5_S8 DELETE_SESSION_REQUEST with dest teid " TEID_FMT " unknown, no sender FTEID, discarding!\n", dsreq.teid);
      return;
    }
  }
}
//------------------------------------------------------------------------------
void pgw_app::handle_itti_msg (itti_s5s8_modify_bearer_request& m)
{
  Logger::pgwc_app().debug("Received S5S8 MODIFY_BEARER_REQUEST sender teid " TEID_FMT "  gtpc_tx_id %" PRIX64"\n", m.teid, m.gtpc_tx_id);
  Logger::pgwc_app().error("TODO rx itti_s5s8_modify_bearer_request");
}


