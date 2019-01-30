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

/*! \file pgw_context.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "itti.hpp"
#include "logger.hpp"
#include "pgw_app.hpp"
#include "pgw_config.hpp"
#include "pgw_context.hpp"
#include "pgwc_procedure.hpp"

#include <algorithm>

using namespace oai::cn::core;
using namespace oai::cn::proto::gtpv2c;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::pgwc;
using namespace std;

extern itti_mw *itti_inst;
extern pgw_app *pgw_app_inst;
extern pgw_config pgw_cfg;

//------------------------------------------------------------------------------
std::string pgw_eps_bearer::toString() const
{
  std::string s = {};
  s.append("EPS BEARER:\n");
  s.append("\tEBI:\t\t\t\t").append(std::to_string(ebi.ebi)).append("\n");
  s.append("\tTFT:\t\t\t\tTODO tft").append("\n");
  s.append("\tSGW FTEID S5S8 UP:\t\t").append(oai::cn::core::toString(sgw_fteid_s5_s8_up)).append("\n");
  s.append("\tPGW FTEID S5S8 UP:\t\t").append(oai::cn::core::toString(pgw_fteid_s5_s8_up)).append("\n");
  s.append("\tBearer QOS:\t\t\t").append(oai::cn::core::toString(eps_bearer_qos)).append("\n");
  return s;
}
//------------------------------------------------------------------------------
void pgw_eps_bearer::deallocate_ressources()
{
  Logger::pgwc_app().info( "TODO remove_eps_bearer(%d) OpenFlow", ebi.ebi);
  if (not is_fteid_zero(pgw_fteid_s5_s8_up))
    pgw_app_inst->free_s5s8_up_fteid(pgw_fteid_s5_s8_up);
  clear();
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::set(const core::paa_t& paa)
{
  switch (paa.pdn_type.pdn_type) {
  case PDN_TYPE_E_IPV4:
    ipv4 = true;
    ipv6 = false;
    ipv4_address = paa.ipv4_address;
    break;
  case PDN_TYPE_E_IPV6:
    ipv4 = false;
    ipv6 = true;
    ipv6_address = paa.ipv6_address;
    break;
  case PDN_TYPE_E_IPV4V6:
    ipv4 = true;
    ipv6 = true;
    ipv4_address = paa.ipv4_address;
    ipv6_address = paa.ipv6_address;
    break;
  case PDN_TYPE_E_NON_IP:
    ipv4 = false;
    ipv6 = false;
    break;
  default:
    Logger::pgwc_app().error( "pgw_pdn_connection::set(core::paa_t) Unknown PDN type %d", paa.pdn_type.pdn_type);
  }
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::add_eps_bearer(pgw_eps_bearer& bearer)
{
  if ((bearer.ebi.ebi >= EPS_BEARER_IDENTITY_FIRST) and (bearer.ebi.ebi <= EPS_BEARER_IDENTITY_LAST)) {
    eps_bearers.insert(std::pair<uint8_t,pgw_eps_bearer>(bearer.ebi.ebi, bearer));
    Logger::pgwc_app().trace( "pgw_pdn_connection::add_eps_bearer(%d) success", bearer.ebi.ebi);
  } else {
    Logger::pgwc_app().error( "pgw_pdn_connection::add_eps_bearer(%d) failed, invalid EBI", bearer.ebi.ebi);
  }
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::remove_eps_bearer(const core::ebi_t& ebi)
{
  pgw_eps_bearer& bearer = eps_bearers.at(ebi.ebi);
  bearer.deallocate_ressources();
  eps_bearers.erase(ebi.ebi);
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::remove_eps_bearer(pgw_eps_bearer& bearer)
{
  core::ebi_t ebi = {.ebi = bearer.ebi.ebi};
  bearer.deallocate_ressources();
  eps_bearers.erase(ebi.ebi);
}

//------------------------------------------------------------------------------
void pgw_pdn_connection::deallocate_ressources(const std::string& apn)
{
  for (std::map<uint8_t,pgw_eps_bearer>::iterator it=eps_bearers.begin(); it!=eps_bearers.end(); ++it) {
    it->second.deallocate_ressources();
  }
  eps_bearers.clear();
  if (ipv4) {
    pgw_app_inst->static_paa_release_address(apn, ipv4_address);
  }
  pgw_app_inst->free_s5s8_cp_fteid(pgw_fteid_s5_s8_cp);
  clear();
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::generate_seid()
{
  // DO it simple now:
  seid = pgw_fteid_s5_s8_cp.teid_gre_key | (((uint64_t)pgw_cfg.instance) << 32)
}
//------------------------------------------------------------------------------
std::string pgw_pdn_connection::toString() const
{
  std::string s = {};
  s.append("PDN CONNECTION:\n");
  s.append("\tPDN type:\t\t\t").append(oai::cn::core::toString(pdn_type)).append("\n");
  if (ipv4)
    s.append("\tPAA IPv4:\t\t\t").append(oai::cn::core::toString(ipv4_address)).append("\n");
  if (ipv6)
    s.append("\tPAA IPv6:\t\t\t").append(oai::cn::core::toString(ipv6_address)).append("\n");
  s.append("\tSGW FTEID S5S8 CP:\t\t").append(oai::cn::core::toString(sgw_fteid_s5_s8_cp)).append("\n");
  s.append("\tPGW FTEID S5S8 CP:\t\t").append(oai::cn::core::toString(pgw_fteid_s5_s8_cp)).append("\n");
  s.append("\tDefault EBI:\t\t\t").append(std::to_string(default_bearer.ebi)).append("\n");
  for (auto it : eps_bearers) {
      s.append(it.second.toString());
  }
  return s;
}

//------------------------------------------------------------------------------
shared_ptr<pgw_pdn_connection> apn_context::insert_pdn_connection(pgw_pdn_connection* p)
{
  shared_ptr<pgw_pdn_connection> sp = shared_ptr<pgw_pdn_connection>(p);
  pdn_connections.push_back(sp);
  return sp;
}
//------------------------------------------------------------------------------
shared_ptr<pgw_pdn_connection> apn_context::find_pdn_connection(const teid_t xgw_s5s8c_teid, const bool is_local_teid)
{
  if (is_local_teid) {
    for (auto it : pdn_connections) {
      if (xgw_s5s8c_teid == it.get()->pgw_fteid_s5_s8_cp.teid_gre_key) {
        return it;
      }
    }
    return shared_ptr<pgw_pdn_connection>(nullptr);
  } else {
    for (auto it : pdn_connections) {
      if (xgw_s5s8c_teid == it.get()->sgw_fteid_s5_s8_cp.teid_gre_key) {
        return it;
      }
    }
    return shared_ptr<pgw_pdn_connection>(nullptr);
  }
}
//------------------------------------------------------------------------------
void apn_context::delete_pdn_connection(std::shared_ptr<pgw_pdn_connection> pdn_connection)
{
  if (pdn_connection.get()) {
    pdn_connection.get()->deallocate_ressources(apn_in_use);
    // remove it from collection
    for (std::list<std::shared_ptr<pgw_pdn_connection>>::iterator it=pdn_connections.begin(); it!=pdn_connections.end(); ++it) {
      if (pdn_connection.get() == (*it).get()) {
        pdn_connection.get()->deallocate_ressources(apn_in_use);
        pdn_connections.erase(it);
        return;
      }
    }
  }
}
//------------------------------------------------------------------------------
void apn_context::deallocate_ressources()
{
  for (std::list<std::shared_ptr<pgw_pdn_connection>>::iterator it=pdn_connections.begin(); it!=pdn_connections.end(); ++it) {
    (*it).get()->deallocate_ressources(apn_in_use);
    pdn_connections.erase(it);
  }
  in_use = false;
  apn_ambr = {0};
}
//------------------------------------------------------------------------------
std::string apn_context::toString() const
{
  std::string s = {};
  s.append("APN CONTEXT:\n");
  s.append("\tIn use:\t\t\t\t").append(std::to_string(in_use)).append("\n");
  s.append("\tAPN:\t\t\t\t").append(apn_in_use).append("\n");
  s.append("\tAPN AMBR Bitrate Uplink:\t").append(std::to_string(apn_ambr.br_ul)).append("\n");
  s.append("\tAPN AMBR Bitrate Downlink:\t").append(std::to_string(apn_ambr.br_dl)).append("\n");
  for (auto it : pdn_connections) {
    s.append(it.get()->toString());
  }
  return s;
}

//------------------------------------------------------------------------------
pdn_duo_t pgw_context::find_pdn_connection(const teid_t xgw_s5s8c_teid, const bool is_local_teid)
{
  for (auto ait : apns) {
    shared_ptr<pgw_pdn_connection> sp = ait.get()->find_pdn_connection(xgw_s5s8c_teid, is_local_teid);
    if (sp.get()) {
      return make_pair(ait, sp);
    }
  }
  return make_pair(nullptr, nullptr);
}
//------------------------------------------------------------------------------
pdn_duo_t pgw_context::find_pdn_connection(const string apn, const teid_t xgw_s5s8c_teid, const bool is_local_teid)
{
  shared_ptr<apn_context> sa = find_apn_context(apn);
  shared_ptr<pgw_pdn_connection> sp = shared_ptr<pgw_pdn_connection>(nullptr);
  if (sa.get()) {
    sp = sa.get()->find_pdn_connection(xgw_s5s8c_teid, is_local_teid);
  }
  return make_pair(sa, sp);
}
//------------------------------------------------------------------------------
void pgw_context::delete_apn_context(shared_ptr<apn_context> sa)
{
  if (sa.get()) {
    for (std::list<std::shared_ptr<apn_context>>::iterator ait=apns.begin(); ait!=apns.end(); ++ait) {
    //for (auto ait : apns) {
      if ((*ait).get() == sa.get()) {
        (*ait).get()->deallocate_ressources();
        apns.erase(ait);
        return;
      }
    }
  }
}
//------------------------------------------------------------------------------
void pgw_context::delete_pdn_connection(shared_ptr<apn_context> sa , shared_ptr<pgw_pdn_connection> sp)
{
  if (sa.get()) {
    sa.get()->delete_pdn_connection(sp);
    if (sa.get()->get_num_pdn_connections() == 0) {
      delete_apn_context(sa);
    }
  }
}
//------------------------------------------------------------------------------
shared_ptr<apn_context> pgw_context::insert_apn(apn_context* a)
{
  shared_ptr<apn_context> sa = shared_ptr<apn_context>(a);
  apns.push_back(sa);
  return sa;
}
//------------------------------------------------------------------------------
shared_ptr<apn_context> pgw_context::find_apn_context(const string apn)
{
  for (auto it : apns) {
    if (0 == apn.compare(it.get()->apn_in_use)) {
      return it;
    }
  }
  return shared_ptr<apn_context>(nullptr);
  // same return nullptr;
}
//------------------------------------------------------------------------------
void pgw_context::handle_itti_msg (itti_s5s8_create_session_request& csreq)
{
  // If PCEF integrated in PGW, TODO create a procedure
  pdn_duo_t apn_pdn = find_pdn_connection(csreq.gtp_ies.apn.access_point_name, csreq.teid);
  shared_ptr<apn_context> sa = apn_pdn.first;
  shared_ptr<pgw_pdn_connection> sp = apn_pdn.second;

  cause_t            cause = {.cause_value = REQUEST_ACCEPTED, .pce = 0, .bce = 0, .cs = 0};
  itti_s5s8_create_session_response *s5s8_csr = new itti_s5s8_create_session_response(TASK_PGWC_APP, TASK_PGWC_S5S8);

  csreq.gtp_ies.get(imsi);
  core::indication_t indication = {};
  if (csreq.gtp_ies.get(indication)) {
    if (indication.uimsi) {
      imsi_unauthenticated_indicator = true;
    }
  }

  if (nullptr == sa.get()) {
    apn_context *a = new (apn_context);
    a->in_use = true;
    a->apn_in_use = csreq.gtp_ies.apn.access_point_name;
    if (csreq.gtp_ies.ie_presence_mask & GTPV2C_CREATE_SESSION_REQUEST_PR_IE_APN_AMBR) {
      a->apn_ambr = csreq.gtp_ies.ambr;
    }
    sa = insert_apn(a);
  } else {
    // TODO update ambr ?
  }
  //------
  // BEARER_CONTEXTS_TO_BE_CREATED
  // TODO BEARER_CONTEXTS_TO_BE_REMOVED
  //------
  if (nullptr == sp.get()) {
    pgw_pdn_connection *p = new (pgw_pdn_connection);
    if (not csreq.gtp_ies.get(p->pdn_type)) {
      // default
      p->pdn_type.pdn_type = PDN_TYPE_E_IPV4;
    }
    p->default_bearer = csreq.gtp_ies.bearer_contexts_to_be_created.at(0).eps_bearer_id;
    p->sgw_fteid_s5_s8_cp = csreq.gtp_ies.sender_fteid_for_cp;
    p->pgw_fteid_s5_s8_cp = pgw_app_inst->generate_s5s8_cp_fteid(pgw_cfg.s5s8_cp.addr4);
    pgw_app_inst->set_s5s8cpgw_fteid_2_pgw_context(p->pgw_fteid_s5_s8_cp, shared_from_this());
    sp = sa.get()->insert_pdn_connection(p);
    // Ignore bearer context to be removed
  } else {
    // TODO bearer context to be removed
  }
  for (auto it : csreq.gtp_ies.bearer_contexts_to_be_created) {
    pgw_eps_bearer& eps_bearer = sp.get()->get_eps_bearer(it.eps_bearer_id);
    eps_bearer.ebi = it.eps_bearer_id;
    eps_bearer.tft = it.tft;
    eps_bearer.pgw_fteid_s5_s8_up = pgw_app_inst->generate_s5s8_up_fteid(pgw_cfg.s5s8_up.addr4);
    // Not now (no split SGW-PGW)
    //eps_bearer.sgw_fteid_s5_s8_up = it.s5_s8_u_sgw_fteid;
    eps_bearer.eps_bearer_qos = it.bearer_level_qos;
    sp.get()->add_eps_bearer(eps_bearer);

    bearer_context_created_within_create_session_response bcc = {};
    core::cause_t bcc_cause = {.cause_value = REQUEST_ACCEPTED, .pce = 0, .bce = 0, .cs = 0};
    bcc.set(eps_bearer.ebi);
    bcc.set(bcc_cause);
    bcc.set(eps_bearer.pgw_fteid_s5_s8_up, 2);
    // only if modified bcc.set(bearer_level_qos);
    s5s8_csr->gtp_ies.add_bearer_context_created(bcc);
  }
  for (auto it : csreq.gtp_ies.bearer_contexts_to_be_removed) {
    pgw_eps_bearer&  eps_bearer = sp.get()->get_eps_bearer(it.eps_bearer_id);
    if (eps_bearer.ebi.ebi == it.eps_bearer_id.ebi) {
      core::cause_t bcc_cause = {.cause_value = REQUEST_ACCEPTED, .pce = 0, .bce = 0, .cs = 0};
      bearer_context_marked_for_removal_within_create_session_response bcc = {};
      bcc.set(eps_bearer.ebi);
      bcc.set(bcc_cause);
      s5s8_csr->gtp_ies.add_bearer_context_marked_for_removal(bcc);
      // remove the bearer
      sp.get()->remove_eps_bearer(it.eps_bearer_id);
    }

    bearer_context_marked_for_removal_within_create_session_response bcc = {};
    core::cause_t bcc_cause = {.cause_value = REQUEST_ACCEPTED, .pce = 0, .bce = 0, .cs = 0};
    bcc.set(it.eps_bearer_id);
    bcc.set(bcc_cause);
    s5s8_csr->gtp_ies.add_bearer_context_marked_for_removal(bcc);
  }

  //------
  // PAA
  //------
  bool set_paa = false;
  paa_t paa = {};
//  if (cause.cause_value == REQUEST_ACCEPTED) {
//    paa.pdn_type = sp.get()->pdn_type;
//    bool paa_res = csreq.gtp_ies.get(paa);
//    if ((not paa_res) || (not is_paa_ip_assigned(paa))) {
//      int ret = pgw_app_inst->static_paa_get_free_paa (sa.get()->apn_in_use, paa);
//      if (ret == RETURNok) {
//        set_paa = true;
//      } else {
//        cause.cause_value = PREFERRED_PDN_TYPE_NOT_SUPPORTED;
//        cause.pce = 1;
//      }
//    }
//  }

  //------
  // PCO
  //------
  core::protocol_configuration_options_t pco_resp = {};
  core::protocol_configuration_options_ids_t pco_ids = {
      .pi_ipcp = 0,
      .ci_dns_server_ipv4_address_request = 0,
      .ci_ip_address_allocation_via_nas_signalling = 0,
      .ci_ipv4_address_allocation_via_dhcpv4 = 0,
      .ci_ipv4_link_mtu_request = 0};

  pgw_app_inst->process_pco_request(csreq.gtp_ies.pco, pco_resp, pco_ids);
  switch (sp.get()->pdn_type.pdn_type) {
  case PDN_TYPE_E_IPV4: {
      // Use NAS by default if no preference is set.
      //
      // For context, the protocol configuration options (PCO) section of the
      // packet from the UE is optional, which means that it is perfectly valid
      // for a UE to send no PCO preferences at all. The previous logic only
      // allocates an IPv4 address if the UE has explicitly set the PCO
      // parameter for allocating IPv4 via NAS signaling (as opposed to via
      // DHCPv4). This means that, in the absence of either parameter being set,
      // the does not know what to do, so we need a default option as well.
      //
      // Since we only support the NAS signaling option right now, we will
      // default to using NAS signaling UNLESS we see a preference for DHCPv4.
      // This means that all IPv4 addresses are now allocated via NAS signaling
      // unless specified otherwise.
      //
      // In the long run, we will want to evolve the logic to use whatever
      // information we have to choose the ``best" allocation method. This means
      // adding new bitfields to pco_ids in pgw_pco.h, setting them in pgw_pco.c
      // and using them here in conditional logic. We will also want to
      // implement different logic between the PDN types.
      if (!pco_ids.ci_ipv4_address_allocation_via_dhcpv4) {
        bool paa_res = csreq.gtp_ies.get(paa);
        if ((not paa_res) || (not is_paa_ip_assigned(paa))) {
          int ret = pgw_app_inst->static_paa_get_free_paa (sa.get()->apn_in_use, paa);
          if (ret == RETURNok) {
            set_paa = true;
          } else {
            cause.cause_value = ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED;
            cause.pce = 1;
          }
        }
      } else {
        // TODO allocation via DHCP
      }
    }
    break;

  case PDN_TYPE_E_IPV6: {
      bool paa_res = csreq.gtp_ies.get(paa);
      if ((not paa_res) || (not is_paa_ip_assigned(paa))) {
        int ret = pgw_app_inst->static_paa_get_free_paa (sa.get()->apn_in_use, paa);
        if (ret == RETURNok) {
          set_paa = true;
        } else {
          cause.cause_value = ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED;
          cause.pce = 1;
        }
      }
    }
    break;

  case PDN_TYPE_E_IPV4V6: {
      bool paa_res = csreq.gtp_ies.get(paa);
      if ((not paa_res) || (not is_paa_ip_assigned(paa))) {
        int ret = pgw_app_inst->static_paa_get_free_paa (sa.get()->apn_in_use, paa);
        if (ret == RETURNok) {
          set_paa = true;
        } else {
          cause.cause_value = ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED;
          cause.pce = 1;
        }
      }
    }
    break;

  case PDN_TYPE_E_NON_IP:
    cause.cause_value = PREFERRED_PDN_TYPE_NOT_SUPPORTED;
    cause.pce = 1;
    break;

  default:
    Logger::pgwc_app().error( "Unknown PDN type %d", sp.get()->pdn_type.pdn_type);
    cause.cause_value = PREFERRED_PDN_TYPE_NOT_SUPPORTED;
    cause.pce = 1;
    break;
  }


  //------
  // GTPV2C-Stack
  //------
  s5s8_csr->gtpc_tx_id = csreq.gtpc_tx_id;
  s5s8_csr->teid = sp.get()->sgw_fteid_s5_s8_cp.teid_gre_key;
  s5s8_csr->r_endpoint = csreq.r_endpoint;

  //------
  // PAA, PCO, s5_s8_pgw_fteid
  //------
  s5s8_csr->gtp_ies.set(cause);
  if (cause.cause_value == REQUEST_ACCEPTED) {
    if (set_paa) {
      s5s8_csr->gtp_ies.set(paa);
      sp.get()->set(paa);
    } else {
      // Valid PAA sent in CSR ?
      bool paa_res = csreq.gtp_ies.get(paa);
      if ((paa_res) && ( is_paa_ip_assigned(paa))) {
        sp.get()->set(paa);
      }
    }
    s5s8_csr->gtp_ies.set(pco_resp);
    s5s8_csr->gtp_ies.set_s5_s8_pgw_fteid(sp.get()->pgw_fteid_s5_s8_cp);
    //apn_restriction
    s5s8_csr->gtp_ies.set(sa.get()->apn_ambr);
    //  pgw_fq_csid = {};
    //  sgw_fq_csid = {};

    session_establishment_procedure* p = new session_establishment_procedure(s5s8_csr);
    insert_procedure(p);
    if (p->run(std::shared_from_this())) {
      // TODO handle error code
      Logger::pgwc_app().info( "S5S8 CREATE_SESSION_REQUEST procedure failed");
      remove_procedure(p);
    } else {
    }
  } else {

  }

  std::shared_ptr<itti_s5s8_create_session_response> msg = std::shared_ptr<itti_s5s8_create_session_response>(s5s8_csr);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::pgwc_app().error( "Could not send ITTI message %s to task TASK_PGWC_S5S8", s5s8_csr->get_msg_name());
  }
}
//------------------------------------------------------------------------------
void pgw_context::handle_itti_msg (itti_s5s8_delete_session_request& dsreq)
{
  std::cout << toString() <<  std::endl;

  core::fteid_t sender_fteid = {};
  bool sender_fteid_present = dsreq.gtp_ies.get(sender_fteid);

  pdn_duo_t apn_pdn = {};
  shared_ptr<apn_context> sa = {};
  shared_ptr<pgw_pdn_connection> sp = {};

  if (sender_fteid_present) {
    apn_pdn = find_pdn_connection(sender_fteid.teid_gre_key, false);
  } else {
    apn_pdn = find_pdn_connection(dsreq.teid, true);
  }
  sa = apn_pdn.first;
  sp = apn_pdn.second;

  if (sp.get()) {
    pgw_app_inst->send_delete_session_response_cause_request_accepted(dsreq.gtpc_tx_id, sp.get()->sgw_fteid_s5_s8_cp.teid_gre_key, dsreq.r_endpoint);
    delete_pdn_connection(sa, sp);
  } else {
    if (sender_fteid_present) {
      pgw_app_inst->send_delete_session_response_cause_context_not_found (dsreq.gtpc_tx_id, sender_fteid.teid_gre_key, dsreq.r_endpoint);
      return;
    }
  }
}
//------------------------------------------------------------------------------
void pgw_context::handle_itti_msg (itti_s5s8_modify_bearer_request& csreq)
{
}
//------------------------------------------------------------------------------
std::string pgw_context::toString() const
{
  std::string s = {};
  s.append("PGW CONTEXT:\n");
  s.append("\tIMSI:\t\t\t\t").append(oai::cn::core::toString(imsi)).append("\n");
  s.append("\tIMSI UNAUTHENTICATED:\t\t").append(std::to_string(imsi_unauthenticated_indicator)).append("\n");
  for (auto it : apns) {
    s.append(it.get()->toString());
  }

  //s.append("\tIMSI:\t"+toString(p.msisdn));
  //apns.reserve(MAX_APN_PER_UE);
  return s;
}

