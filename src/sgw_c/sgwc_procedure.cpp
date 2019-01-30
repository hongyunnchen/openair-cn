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

#include "common_defs.h"
#include "itti.hpp"
#include "itti_msg_s11.hpp"
#include "itti_msg_s5s8.hpp"
#include "logger.hpp"
#include "sgwc_app.hpp"
#include "sgwc_config.hpp"
#include "sgwc_procedure.hpp"
#include "sgwc_eps_bearer_context.hpp"

using namespace oai::cn::core;
using namespace oai::cn::core::itti;
using namespace oai::cn::proto::gtpv2c;
using namespace oai::cn::nf::sgwc;
using namespace std;

extern itti_mw *itti_inst;
extern sgwc_app *sgwc_app_inst;
extern sgwc_config sgwc_cfg;

uint64_t oai::cn::nf::sgwc::sebc_procedure::gtpc_tx_id_generator = 0; //even in any case/

//------------------------------------------------------------------------------
int create_session_request_procedure::run(shared_ptr<sgw_eps_bearer_context> c)
{

  // TODO check if compatible with ongoing procedures if any
  //for (auto p : pending_procedures) {
  //  if (p) {
  //
  //  }
  //}
  shared_ptr<sgw_pdn_connection> pdn = c.get()->find_pdn_connection(msg.gtp_ies.apn.access_point_name, msg.gtp_ies.pdn_type);
  if (nullptr != pdn.get()) {
    return RETURNerror;
  } else {
    ebc = c;

    sgw_pdn_connection* p = new sgw_pdn_connection();
    p->apn_in_use = msg.gtp_ies.apn.access_point_name;
    p->pdn_type = msg.gtp_ies.pdn_type;
    shared_ptr<sgw_pdn_connection> spc = ebc.get()->insert_pdn_connection(p);
    // TODO : default_bearer
    p->default_bearer = msg.gtp_ies.bearer_contexts_to_be_created.at(0).eps_bearer_id;
    p->sgw_fteid_s5_s8_cp = sgwc_app_inst->generate_s5s8_cp_fteid(sgwc_cfg.s5s8_cp.addr4);
    sgwc_app_inst->set_s5s8sgw_teid_2_sgw_contexts(p->sgw_fteid_s5_s8_cp.teid_gre_key, c, spc);

    // Forward to P-GW (temp use ITTI instead of ITTI/GTPv2-C/UDP)
    itti_s5s8_create_session_request *s5s8_csr = new itti_s5s8_create_session_request(TASK_SGWC_APP, TASK_SGWC_S5S8);
    s5s8_csr->gtpc_tx_id = this->gtpc_tx_id;

    // transfer IEs from S11 msg to S5 msg
    // Mandatory imsi
    imsi_t imsi = {}; if (msg.gtp_ies.get(imsi)) s5s8_csr->gtp_ies.set(imsi);
    // The IE shall be included for the case of a UE Requested PDN Connectivity, if the MME has it stored for that UE.
    // It shall be included when used on the S5/S8 interfaces if provided by the MME/SGSN:
    msisdn_t msisdn = {}; if (msg.gtp_ies.get(msisdn)) s5s8_csr->gtp_ies.set(msisdn);
    // If the SGW receives this IE, it shall forward it to the PGW on the S5/S8 interface:
    mei_t mei = {}; if (msg.gtp_ies.get(mei)) s5s8_csr->gtp_ies.set(mei);
    // The SGW shall include this IE on S5/S8 if it receives the ULI from MME/SGSN.
    uli_t uli = {}; if (msg.gtp_ies.get(uli)) s5s8_csr->gtp_ies.set(uli);
    // No Serving Network
    // Mandatory rat_type
    rat_type_t rat_type = {}; if (msg.gtp_ies.get(rat_type)) s5s8_csr->gtp_ies.set(rat_type);
    // Conditional. tweak this later
    indication_t indication = {}; if (msg.gtp_ies.get(indication)) s5s8_csr->gtp_ies.set(indication);
    // Mandatory
    s5s8_csr->gtp_ies.set_sender_fteid_for_cp(p->sgw_fteid_s5_s8_cp);
    // Conditional
    fteid_t fteid = {}; if (msg.gtp_ies.get_pgw_s5s8_address_for_cp(fteid)) s5s8_csr->gtp_ies.set_pgw_s5s8_address_for_cp(fteid);
    // Mandatory
    apn_t apn = {}; if (msg.gtp_ies.get(apn)) s5s8_csr->gtp_ies.set(apn);
    // Conditional
    selection_mode_t selection_mode = {}; if (msg.gtp_ies.get(selection_mode)) s5s8_csr->gtp_ies.set(selection_mode);
    // Conditional
    pdn_type_t pdn_type = {}; if (msg.gtp_ies.get(pdn_type)) s5s8_csr->gtp_ies.set(pdn_type);
    // Conditional
    paa_t paa = {}; if (msg.gtp_ies.get(paa)) s5s8_csr->gtp_ies.set(paa);
    // Conditional
    apn_restriction_t apn_restriction = {}; if (msg.gtp_ies.get(apn_restriction)) s5s8_csr->gtp_ies.set(apn_restriction);
    // Conditional
    ambr_t ambr = {}; if (msg.gtp_ies.get(ambr)) s5s8_csr->gtp_ies.set(ambr);
    // Conditional
    protocol_configuration_options_t protocol_configuration_options = {}; if (msg.gtp_ies.get(protocol_configuration_options)) s5s8_csr->gtp_ies.set(protocol_configuration_options);
    if (msg.gtp_ies.has_bearer_context_to_be_created()) {
      for (auto i : msg.gtp_ies.bearer_contexts_to_be_created) {
        bearer_context_to_be_created_within_create_session_request b = {};
        ebi_t ebi = {}; if (i.get(ebi)) b.set(ebi);
        bearer_qos_t bearer_qos = {}; if (i.get(bearer_qos)) b.set(bearer_qos);
        // get_s5_s8_u_sgw_fteid
        fteid_t s5s8_up_fteid = spc.get()->generate_s5s8_up_fteid(sgwc_cfg.s5s8_up.addr4, bearer_qos);
        b.set_s5_s8_u_sgw_fteid(s5s8_up_fteid);
        s5s8_csr->gtp_ies.add_bearer_context_to_be_created(b);

        core::ebi_t cebi = {.ebi = ebi};
        sgw_eps_bearer* eps_bearer = new sgw_eps_bearer();
        eps_bearer->ebi = cebi;
        eps_bearer->sgw_fteid_s5_s8_up = s5s8_up_fteid;
        eps_bearer->eps_bearer_qos = bearer_qos;
        spc.get()->add_eps_bearer(std::shared_ptr<sgw_eps_bearer>(eps_bearer));
      }
    }
    if (msg.gtp_ies.has_bearer_context_to_be_removed()) {
      for (auto i : msg.gtp_ies.bearer_contexts_to_be_removed) {
        bearer_context_to_be_removed_within_create_session_request b = {};
        ebi_t ebi = {}; if (i.get(ebi)) b.set(ebi);
        s5s8_csr->gtp_ies.add_bearer_context_to_be_removed(b);

        core::ebi_t cebi = {.ebi = ebi};
        std::shared_ptr<sgw_eps_bearer> seb = spc.get()->get_eps_bearer(cebi);
        seb.get()->deallocate_ressources();
        // TODO check when have to remove the bearer
        spc.get()->remove_eps_bearer(seb);
      }
    }

    //s5s8_csr->gtp_ies = msg.gtp_ies;
    //s5s8_csr->l_endpoint = {};
    //s5s8_csr->r_endpoint = {};

    std::shared_ptr<itti_s5s8_create_session_request> msg = std::shared_ptr<itti_s5s8_create_session_request>(s5s8_csr);
    int ret = itti_inst->send_msg(msg);
    if (RETURNok != ret) {
      Logger::sgwc_app().error( "Could not send ITTI message %s to task TASK_SGWC_S5S8", s5s8_csr->get_msg_name());
      return RETURNerror;
    }
    return RETURNok;
  }
}


//------------------------------------------------------------------------------
void create_session_request_procedure::handle_itti_msg (core::itti::itti_s5s8_create_session_response& csresp, std::shared_ptr<sgw_eps_bearer_context> ebc, std::shared_ptr<sgw_pdn_connection> pdn)
{
  //TODO Get PDN connection and fill the field
  if (nullptr == pdn.get()) {
    Logger::sgwc_app().error( "create_session_request_procedure handling CREATE_SESSION_RESPONSE, Could not get sgw_pdn_connection object, discarding");
    return;
  }

  itti_s11_create_session_response *s11_csresp = new itti_s11_create_session_response(TASK_SGWC_APP, TASK_SGWC_S11);
  s11_csresp->gtpc_tx_id = this->gtpc_tx_id;
  s11_csresp->r_endpoint = this->msg.r_endpoint;
  s11_csresp->teid = this->msg.gtp_ies.sender_fteid_for_cp.teid_gre_key;

  // transfer IEs from S5 msg to S11 msg
  // Mandatory imsi
  core::cause_t cause = {}; if (csresp.gtp_ies.get(cause)) s11_csresp->gtp_ies.set(cause);

  csresp.gtp_ies.get_s5_s8_pgw_fteid(pdn.get()->pgw_fteid_s5_s8_cp);

  s11_csresp->gtp_ies.set_sender_fteid_for_cp(ebc.get()->sgw_fteid_s11_s4_cp);

  paa_t paa = {}; if (csresp.gtp_ies.get(paa)) s11_csresp->gtp_ies.set(paa);
  apn_restriction_t apn_restriction = {}; if (csresp.gtp_ies.get(apn_restriction)) s11_csresp->gtp_ies.set(apn_restriction);
  ambr_t ambr = {}; if (csresp.gtp_ies.get(ambr)) s11_csresp->gtp_ies.set(ambr);
  //ebi_t ebi = {}; if (msg.gtp_ies.get(ebi)) s11_csresp->gtp_ies.set(ebi);
  core::protocol_configuration_options_t pco = {}; if (csresp.gtp_ies.get(pco)) s11_csresp->gtp_ies.set(pco);

  fq_csid_t fq_csid = {}; if (msg.gtp_ies.get(fq_csid,0)) s11_csresp->gtp_ies.set(fq_csid,0);
  // TODO FQCSID instance 1
  //  local_distinguished_name_t ldn = {}; if (msg.gtp_ies.get(ldn,1)) ;
  epc_timer_t pgw_back_off_time = {}; if (csresp.gtp_ies.get(pgw_back_off_time)) s11_csresp->gtp_ies.set(pgw_back_off_time);
  indication_t indication = {}; if (csresp.gtp_ies.get(indication)) s11_csresp->gtp_ies.set(indication);


  if (csresp.gtp_ies.has_bearer_context_created()) {
    for (auto i : csresp.gtp_ies.bearer_contexts_created) {
      bearer_context_created_within_create_session_response b = {};
      cause_t cause = {}; if (i.get(cause)) b.set(cause);
      core::ebi_t ebi = {}; if (i.get(ebi)) b.set(ebi);
      if (cause.cause_value == REQUEST_ACCEPTED) {
        core::ebi_t cebi = {.ebi = ebi};
        std::shared_ptr<sgw_eps_bearer> seb = pdn.get()->get_eps_bearer(cebi);
        if (seb.get()) {
          seb.get()->ebi = cebi;
          i.get(seb.get()->eps_bearer_qos);
          i.get(seb.get()->pgw_fteid_s5_s8_up, 2);

#define SPGW_PLIT 0
#if !SPGW_SPLIT
          seb.get()->sgw_fteid_s1u_s12_s4u_s11u = seb.get()->pgw_fteid_s5_s8_up;
#else
          // TODO
#endif
          if (not is_fteid_zero(seb.get()->sgw_fteid_s1u_s12_s4u_s11u)) b.set_s1_u_sgw_fteid(seb.get()->sgw_fteid_s1u_s12_s4u_s11u);
          core::bearer_qos_t bearer_qos = {};
          if (i.get(bearer_qos)) {
            b.set(bearer_qos);
          }
        }
      }
      s11_csresp->gtp_ies.add_bearer_context_created(b);
    }
  }
  if (csresp.gtp_ies.has_bearer_context_marked_for_removal()) {
    for (auto i : csresp.gtp_ies.bearer_contexts_marked_for_removal) {
      bearer_context_marked_for_removal_within_create_session_response b = {};
      core::cause_t cause = {}; if (i.get(cause)) b.set(cause);
      core::ebi_t ebi = {}; if (i.get(ebi)) b.set(ebi);
      s11_csresp->gtp_ies.add_bearer_context_marked_for_removal(b);

      core::ebi_t cebi = {.ebi = ebi};
      std::shared_ptr<sgw_eps_bearer> seb = pdn.get()->get_eps_bearer(cebi);
      if (seb.get()) {
        seb.get()->clear();
      }
    }
  }


  std::shared_ptr<itti_s11_create_session_response> msg_send = std::shared_ptr<itti_s11_create_session_response>(s11_csresp);
  int ret = itti_inst->send_msg(msg_send);
  if (RETURNok != ret) {
    Logger::sgwc_app().error( "Could not send ITTI message %s to task TASK_SGW_11", s11_csresp->get_msg_name());
  }
}
//------------------------------------------------------------------------------
int delete_session_request_procedure::run(shared_ptr<sgw_eps_bearer_context> c)
{
  if (nullptr == c.get()) {
    return RETURNerror;
  } else {
    ebc = c;

    core::indication_t indication = {};
    bool oi_set = false;
    if (msg.gtp_ies.get(indication)) {
      if (indication.oi) {
        oi_set = true;
      }
    }

    // Forward to P-GW (temp use ITTI instead of ITTI/GTPv2-C/UDP)
    itti_s5s8_delete_session_request *s5s8_dsr = new itti_s5s8_delete_session_request(TASK_SGWC_APP, TASK_SGWC_S5S8);
    s5s8_dsr->gtpc_tx_id = this->gtpc_tx_id;
    s5s8_dsr->teid = pdn_connection.get()->pgw_fteid_s5_s8_cp.teid_gre_key;

    // transfer IEs from S11 msg to S5 msg
    // The SGW shall include this IE on S5/S8 if it receives the Cause from the MME/SGSN.
    core::cause_t cause = {}; if (msg.gtp_ies.get(cause)) s5s8_dsr->gtp_ies.set(cause);

    // This IE shall be included on the S4/S11, S5/S8 and S2a/S2b interfaces to indicate the default bearer
    // associated with the PDN being disconnected unless in the handover/TAU/RAU with SGW relocation procedures.
    core::ebi_t ebi = {};
    if (msg.gtp_ies.get(ebi)) {
      s5s8_dsr->gtp_ies.set(ebi);
    } else {
      s5s8_dsr->gtp_ies.set(pdn_connection.get()->default_bearer);
    }
    // The MME/SGSN shall include this IE on the S4/S11 interface for the Detach procedure. The MME shall include
    // ECGI, SGSN shall include CGI/SAI. The SGW shall include this IE on S5/S8 if it receives the ULI from MME/SGSN.
    core::uli_t uli = {}; if (msg.gtp_ies.get(uli)) s5s8_dsr->gtp_ies.set(uli);

    // If the UE includes the PCO IE, then the MME/SGSN shall Configuration Options copy the content of this IE transparently from the PCO IE
    // (PCO) included by the UE. If SGW receives the PCO IE, SGW shall forward it to PGW.
    core::protocol_configuration_options_t pco = {}; if (msg.gtp_ies.get(pco)) s5s8_dsr->gtp_ies.set(pco);

    // C This IE may be included on the S5/S8 and S2a/S2b interfaces.
    // If the Sender F-TEID for Control Plane is received by the PGW, the PGW shall only accept the Delete Session
    // Request message when the Sender F-TEID for Control Plane in this message is the same as the Sender F-TEID
    // for Control Plane that was last received in either the Create Session Request message or the Modify Bearer Request
    // message on the given interface. See NOTE 6.
    // CO The SGW shall include this IE on the S5/S8 interface if the Delete Session Request is sent to clean up a hanging PDN
    // connection context in the PGW, i.e. as a result of receiving a Create Session Request at the SGW colliding with an
    // existing PDN connection context (see subclause 7.2.1).
    s5s8_dsr->gtp_ies.set_sender_fteid_for_cp(pdn_connection.get()->sgw_fteid_s5_s8_cp);

    if (oi_set) {
      // The SGW shall forward this IE on the S5/S8 interface if the SGW receives it from the MME/SGSN, and if the Operation
      // Indication bit received from the MME/SGSN is set to 1.
      core::ue_time_zone_t ue_time_zone = {}; if (msg.gtp_ies.get(ue_time_zone)) s5s8_dsr->gtp_ies.set(ue_time_zone);

      // The MME shall include this IE on the S11 interface to indicate the NAS release cause to release the PDN
      // connection, if available and this information is permitted to be sent to the PGW operator according to MME operator's policy.
      // The SGW shall include this IE on the S5/S8 interface if it receives it from the MME and if the Operation Indication bit
      // received from the MME is set to 1.
      core::ran_nas_cause_t ran_nas_cause = {}; if (msg.gtp_ies.get(ran_nas_cause)) s5s8_dsr->gtp_ies.set(ran_nas_cause);
    }

    // If the UE includes the ePCO IE, then the MME shall copy the content of this IE transparently from the ePCO IE included by the UE.
    // If the SGW receives the ePCO IE, the SGW shall forward it to the PGW.
    core::extended_protocol_configuration_options_t epco = {}; if (msg.gtp_ies.get(epco)) s5s8_dsr->gtp_ies.set(epco);

    std::shared_ptr<itti_s5s8_delete_session_request> msg = std::shared_ptr<itti_s5s8_delete_session_request>(s5s8_dsr);
    int ret = itti_inst->send_msg(msg);
    if (RETURNok != ret) {
      Logger::sgwc_app().error( "Could not send ITTI message %s to task TASK_SGWC_S5S8", s5s8_dsr->get_msg_name());
      return RETURNerror;
    }
    return RETURNok;
  }
}
//------------------------------------------------------------------------------
void delete_session_request_procedure::handle_itti_msg (core::itti::itti_s5s8_delete_session_response& dsresp, std::shared_ptr<sgw_eps_bearer_context> ebc, std::shared_ptr<sgw_pdn_connection> pdn)
{
  itti_s11_delete_session_response *s11_dsresp = new itti_s11_delete_session_response(TASK_SGWC_APP, TASK_SGWC_S11);
  s11_dsresp->gtpc_tx_id = this->gtpc_tx_id;
  s11_dsresp->r_endpoint = this->msg.r_endpoint;
  s11_dsresp->teid = this->ebc.get()->mme_fteid_s11.teid_gre_key;
;

  // transfer IEs from S5 msg to S11 msg
  core::cause_t cause = {};
  if (dsresp.gtp_ies.get(cause)) {
    s11_dsresp->gtp_ies.set(cause);
  } else {
    Logger::sgwc_app().error( "Could not get CAUSE in S5S8 DELETE_SESSION_RESPONSE");
  }

  //TODO Get PDN connection and fill the field
  if (nullptr == pdn.get()) {
    Logger::sgwc_app().error( "Could not get sgw_pdn_connection object");
    return;
  }
  // Delete PDN connection even if s5s8 cause is not success
  ebc->delete_pdn_connection(pdn);

  std::shared_ptr<itti_s11_delete_session_response> msg = std::shared_ptr<itti_s11_delete_session_response>(s11_dsresp);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::sgwc_app().error( "Could not send ITTI message %s to task TASK_SGWC_S11", s11_dsresp->get_msg_name());
  }
}
//------------------------------------------------------------------------------
int modify_bearer_request_procedure::run(shared_ptr<sgw_eps_bearer_context> c)
{
  if (nullptr == c.get()) {
    return RETURNerror;
  } else {
    ebc = c;

    std::shared_ptr<sgw_pdn_connection> pdn = std::shared_ptr<sgw_pdn_connection>(nullptr);
    if (msg.gtp_ies.has_bearer_context_to_be_modified()) {
      for (auto it : msg.gtp_ies.bearer_contexts_to_be_modified) {
        // bearer_context_to_be_modified_within_modify_bearer_request
        if (pdn.get() == nullptr) {
          pdn = c.get()->find_pdn_connection(it.eps_bearer_id);
        }
        if (pdn.get() == nullptr) {
          // TODO ;
        } else {
          // check if bearer belongs to same pdn connection
          std::shared_ptr<sgw_pdn_connection> pdn_check = c.get()->find_pdn_connection(it.eps_bearer_id);
        }

      }
    }
    return RETURNok;
  }
}

