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

/*! \file mme_s11.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "common_defs.h"
#include "3gpp_24.008.h"
#include "itti.hpp"
#include "itti_msg_s11.hpp"
#include "logger.hpp"
#include "mme_s11.hpp"
#include "pgw_config.hpp"
#include "sgwc_config.hpp"
#include <stdexcept>

using namespace oai::cn::core;
using namespace oai::cn::proto::gtpv2c;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::sgwc;
using namespace std;

extern itti_mw *itti_inst;
extern oai::cn::nf::pgwc::pgw_config pgw_cfg;
extern sgwc_config sgwc_cfg;
extern mme_s11  *mme_s11_inst;

oai::cn::core::imsi_t imsi = {};
oai::cn::core::fteid_t sender_fteid_for_cp = {};
int num_proc = 0;


timer_id_t start_timer = {};
void mme_s11_task (void*);


void increment_imsi()
{
  imsi.u1.digits.digit15 += 1;
  if (imsi.u1.digits.digit15 > 9) {
    imsi.u1.digits.digit14 += 1;
    if (imsi.u1.digits.digit14 > 9) {
      imsi.u1.digits.digit13 += 1;
      if (imsi.u1.digits.digit13 > 9) {
        imsi.u1.digits.digit12 += 1;
        if (imsi.u1.digits.digit12 > 9) {
          imsi.u1.digits.digit11 += 1;
          if (imsi.u1.digits.digit11 > 9) {
            imsi.u1.digits.digit10 += 1;
            if (imsi.u1.digits.digit10 > 9) {
              imsi.u1.digits.digit9 += 1;
              if (imsi.u1.digits.digit9 > 9) {
                imsi.u1.digits.digit8 += 1;
                if (imsi.u1.digits.digit8 > 9) {
                  imsi.u1.digits.digit7 += 1;
                }
              }
            }
          }
        }
      }
    }
  }
}
//------------------------------------------------------------------------------
void mme_s11_task (void *args_p)
{
  const task_id_t task_id = TASK_MME_S11;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {

    case S11_CREATE_SESSION_REQUEST:
      Logger::mme_s11().error( "Received S11_CREATE_SESSION_REQUEST");
      break;
    case S11_DELETE_SESSION_REQUEST:
      Logger::mme_s11().error( "Received S11_DELETE_SESSION_REQUEST");
      break;
    case S11_MODIFY_BEARER_REQUEST:
      Logger::mme_s11().error( "Received S11_MODIFY_BEARER_REQUEST");
      break;
    case S11_RELEASE_ACCESS_BEARERS_REQUEST:
      Logger::mme_s11().error( "Received S11_RELEASE_ACCESS_BEARERS_REQUEST");
      break;

    case S11_CREATE_SESSION_RESPONSE:
      if (itti_s11_create_session_response* m = dynamic_cast<itti_s11_create_session_response*>(msg)) {
        if (m->gtp_ies.cause.cause_value == REQUEST_ACCEPTED) {
          Logger::mme_s11().debug( "Received S11_CREATE_SESSION_RESPONSE");
          mme_s11_inst->send_modify_bearer_request(m->gtp_ies.sender_fteid_for_cp.teid_gre_key);
        } else {
          Logger::mme_s11().error( "Received S11_CREATE_SESSION_RESPONSE Failed");
        }
      }
      break;
    case S11_DELETE_SESSION_RESPONSE:
      if (itti_s11_delete_session_response* m = dynamic_cast<itti_s11_delete_session_response*>(msg)) {
        if (m->gtp_ies.cause.cause_value == REQUEST_ACCEPTED) {
          Logger::mme_s11().debug( "Received S11_DELETE_SESSION_RESPONSE");
          mme_s11_inst->release_s11_cp_teid(m->teid);
          num_proc ++;
          if (num_proc <= 250) {
            increment_imsi();
            mme_s11_inst->send_create_session_request();
          }
        } else {
          Logger::mme_s11().error( "Received S11_DELETE_SESSION_RESPONSE Failed");
        }
      }
      break;
    case S11_MODIFY_BEARER_RESPONSE:
      if (itti_s11_modify_bearer_response* m = dynamic_cast<itti_s11_modify_bearer_response*>(msg)) {
        Logger::mme_s11().debug( "Received S11_MODIFY_BEARER_RESPONSE");
      }
      break;
    case S11_RELEASE_ACCESS_BEARERS_RESPONSE:
      if (itti_s11_release_access_bearers_response* m = dynamic_cast<itti_s11_release_access_bearers_response*>(msg)) {
        Logger::mme_s11().debug( "Received S11_RELEASE_ACCESS_BEARERS_RESPONSE");
      }
      break;

    case TIME_OUT:
      if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
        Logger::mme_s11().info( "TIME-OUT event timer id %d", to->timer_id);
        mme_s11_inst->time_out_itti_event(to->timer_id);
      }
      break;
    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::mme_s11().info( "Received terminate message");
        return;
      }
      break;
    default:
      Logger::mme_s11().info( "no handler for msg type %d", msg->msg_type);
    }

  } while (true);
}


//------------------------------------------------------------------------------
mme_s11::mme_s11 () : gtpv2c_stack(string(inet_ntoa(sgwc_cfg.s11_cp.addr4)), 4123)
{
  Logger::mme_s11().startup("Starting...");

  imsi.u1.digits.digit1 = 2;
  imsi.u1.digits.digit2 = 0;
  imsi.u1.digits.digit3 = 8;
  imsi.u1.digits.digit4 = 9;
  imsi.u1.digits.digit5 = 3;
  imsi.u1.digits.digit6 = 0;
  imsi.u1.digits.digit7 = 0;
  imsi.u1.digits.digit8 = 0;
  imsi.u1.digits.digit9 = 0;
  imsi.u1.digits.digit10 = 0;
  imsi.u1.digits.digit11 = 0;
  imsi.u1.digits.digit12 = 0;
  imsi.u1.digits.digit13 = 0;
  imsi.u1.digits.digit14 = 0;
  imsi.u1.digits.digit15 = 0;
  imsi.u1.digits.filler = 0xF;
  imsi.num_digits = 15;

  teid_s11_cp = 0;

  if (itti_inst->create_task(TASK_MME_S11, mme_s11_task, nullptr) ) {
    Logger::mme_s11().error( "Cannot create task TASK_MME_S11" );
    throw std::runtime_error( "Cannot create task TASK_MME_S11" );
  }
  start_timer = itti_inst->timer_setup(1,0, TASK_MME_S11);
  Logger::mme_s11().startup( "Started" );
}
//------------------------------------------------------------------------------
teid_t mme_s11::generate_s11_cp_teid()
{
  teid_t loop_detect_teid = teid_s11_cp;
  teid_t teid =  ++teid_s11_cp;
  while ((is_s11c_teid_exist(teid)) || (teid == UNASSIGNED_TEID)) {
    teid =  ++teid_s11_cp;
    if (loop_detect_teid == teid) return UNASSIGNED_TEID;
  }
  s11cpplteid.insert(teid);
  return teid;
}
//------------------------------------------------------------------------------
void mme_s11::release_s11_cp_teid(teid_t teid)
{
  s11cpplteid.erase(teid);
}
//------------------------------------------------------------------------------
bool mme_s11::is_s11c_teid_exist(const teid_t& teid_s11_cp) const
{
  return bool{s11cpplteid.count(teid_s11_cp) > 0};
}
//------------------------------------------------------------------------------
void mme_s11::send_s11_msg(itti_s11_create_session_request& i)
{
  send_initial_message(i.r_endpoint, i.teid, i.gtp_ies, TASK_MME_S11, i.gtpc_tx_id);
}
//------------------------------------------------------------------------------
void mme_s11::send_s11_msg(itti_s11_delete_session_request& i)
{
  send_initial_message(i.r_endpoint, i.teid, i.gtp_ies, TASK_MME_S11, i.gtpc_tx_id);
}
//------------------------------------------------------------------------------
void mme_s11::send_s11_msg(itti_s11_modify_bearer_request& i)
{
  send_initial_message(i.r_endpoint, i.teid, i.gtp_ies, TASK_MME_S11, i.gtpc_tx_id);
}
//------------------------------------------------------------------------------
void mme_s11::handle_receive_create_session_response(gtpv2c_msg& msg, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
  bool error = true;
  uint64_t gtpc_tx_id = 0;
  gtpv2c_create_session_response msg_ies_container = {};
  msg.to_core_type(msg_ies_container);

  handle_receive_message_cb(msg, remote_endpoint, TASK_MME_S11, error, gtpc_tx_id);
  if (!error) {
    itti_s11_create_session_response *itti_msg = new itti_s11_create_session_response(TASK_MME_S11, TASK_MME_S11);
    itti_msg->gtp_ies = msg_ies_container;
    itti_msg->r_endpoint = remote_endpoint;
    itti_msg->gtpc_tx_id = gtpc_tx_id;
    itti_msg->teid = msg.get_teid();
    std::shared_ptr<itti_s11_create_session_response> i = std::shared_ptr<itti_s11_create_session_response>(itti_msg);
    int ret = itti_inst->send_msg(i);
    if (RETURNok != ret) {
      Logger::mme_s11().error( "Could not send ITTI message %s to task TASK_MME_S11", i.get()->get_msg_name());
    }
  }
}
//------------------------------------------------------------------------------
void mme_s11::handle_receive_delete_session_response(gtpv2c_msg& msg, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
  bool error = true;
  uint64_t gtpc_tx_id = 0;
  gtpv2c_delete_session_response msg_ies_container = {};
  msg.to_core_type(msg_ies_container);

  handle_receive_message_cb(msg, remote_endpoint, TASK_MME_S11, error, gtpc_tx_id);
  if (!error) {
    itti_s11_delete_session_response *itti_msg = new itti_s11_delete_session_response(TASK_MME_S11, TASK_MME_S11);
    itti_msg->gtp_ies = msg_ies_container;
    itti_msg->r_endpoint = remote_endpoint;
    itti_msg->gtpc_tx_id = gtpc_tx_id;
    itti_msg->teid = msg.get_teid();
    std::shared_ptr<itti_s11_delete_session_response> i = std::shared_ptr<itti_s11_delete_session_response>(itti_msg);
    int ret = itti_inst->send_msg(i);
    if (RETURNok != ret) {
      Logger::mme_s11().error( "Could not send ITTI message %s to task TASK_MME_S11", i.get()->get_msg_name());
    }
  }
}
//------------------------------------------------------------------------------
void mme_s11::handle_receive_gtpv2c_msg(gtpv2c_msg& msg, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
  Logger::mme_s11().info( "handle_receive_gtpv2c_msg msg type %d length %d", msg.get_message_type(), msg.get_message_length());
  switch (msg.get_message_type()) {
  case GTP_CREATE_SESSION_RESPONSE: {
    handle_receive_create_session_response(msg, remote_endpoint);
  }
  break;
  case GTP_DELETE_SESSION_RESPONSE: {
    handle_receive_delete_session_response(msg, remote_endpoint);
  }
  break;
  case GTP_CREATE_SESSION_REQUEST:
  case GTP_ECHO_REQUEST:
  case GTP_ECHO_RESPONSE:
  case GTP_VERSION_NOT_SUPPORTED_INDICATION:
  case GTP_MODIFY_BEARER_REQUEST:
  case GTP_MODIFY_BEARER_RESPONSE:
  case GTP_DELETE_SESSION_REQUEST:
  case GTP_CHANGE_NOTIFICATION_REQUEST:
  case GTP_CHANGE_NOTIFICATION_RESPONSE:
  case GTP_REMOTE_UE_REPORT_NOTIFICATION:
  case GTP_REMOTE_UE_REPORT_ACKNOWLEDGE:
  case GTP_MODIFY_BEARER_COMMAND:
  case GTP_MODIFY_BEARER_FAILURE_INDICATION:
  case GTP_DELETE_BEARER_COMMAND:
  case GTP_DELETE_BEARER_FAILURE_INDICATION:
  case GTP_BEARER_RESOURCE_COMMAND:
  case GTP_BEARER_RESOURCE_FAILURE_INDICATION:
  case GTP_DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION:
  case GTP_TRACE_SESSION_ACTIVATION:
  case GTP_TRACE_SESSION_DEACTIVATION:
  case GTP_STOP_PAGING_INDICATION:
  case GTP_CREATE_BEARER_REQUEST:
  case GTP_CREATE_BEARER_RESPONSE:
  case GTP_UPDATE_BEARER_REQUEST:
  case GTP_UPDATE_BEARER_RESPONSE:
  case GTP_DELETE_BEARER_REQUEST:
  case GTP_DELETE_BEARER_RESPONSE:
  case GTP_DELETE_PDN_CONNECTION_SET_REQUEST:
  case GTP_DELETE_PDN_CONNECTION_SET_RESPONSE:
  case GTP_PGW_DOWNLINK_TRIGGERING_NOTIFICATION:
  case GTP_PGW_DOWNLINK_TRIGGERING_ACKNOWLEDGE:
  case GTP_IDENTIFICATION_REQUEST:
  case GTP_IDENTIFICATION_RESPONSE:
  case GTP_CONTEXT_REQUEST:
  case GTP_CONTEXT_RESPONSE:
  case GTP_CONTEXT_ACKNOWLEDGE:
  case GTP_FORWARD_RELOCATION_REQUEST:
  case GTP_FORWARD_RELOCATION_RESPONSE:
  case GTP_FORWARD_RELOCATION_COMPLETE_NOTIFICATION:
  case GTP_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE:
  case GTP_FORWARD_ACCESS_CONTEXT_NOTIFICATION:
  case GTP_FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE:
  case GTP_RELOCATION_CANCEL_REQUEST:
  case GTP_RELOCATION_CANCEL_RESPONSE:
  case GTP_CONFIGURATION_TRANSFER_TUNNEL_MESSAGE:
  case GTP_DETACH_NOTIFICATION:
  case GTP_DETACH_ACKNOWLEDGE:
  case GTP_CS_PAGING_INDICATION:
  case GTP_RAN_INFORMATION_RELAY:
  case GTP_ALERT_MME_NOTIFICATION:
  case GTP_ALERT_MME_ACKNOWLEDGE:
  case GTP_UE_ACTIVITY_NOTIFICATION:
  case GTP_UE_ACTIVITY_ACKNOWLEDGE:
  case GTP_ISR_STATUS_INDICATION:
  case GTP_UE_REGISTRATION_QUERY_REQUEST:
  case GTP_UE_REGISTRATION_QUERY_RESPONSE:
  case GTP_CREATE_FORWARDING_TUNNEL_REQUEST:
  case GTP_CREATE_FORWARDING_TUNNEL_RESPONSE:
  case GTP_SUSPEND_NOTIFICATION:
  case GTP_SUSPEND_ACKNOWLEDGE:
  case GTP_RESUME_NOTIFICATION:
  case GTP_RESUME_ACKNOWLEDGE:
  case GTP_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST:
  case GTP_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE:
  case GTP_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST:
  case GTP_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE:
  case GTP_RELEASE_ACCESS_BEARERS_REQUEST:
  case GTP_RELEASE_ACCESS_BEARERS_RESPONSE:
  case GTP_DOWNLINK_DATA_NOTIFICATION:
  case GTP_DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE:
  case GTP_PGW_RESTART_NOTIFICATION:
  case GTP_PGW_RESTART_NOTIFICATION_ACKNOWLEDGE:
  case GTP_UPDATE_PDN_CONNECTION_SET_REQUEST:
  case GTP_UPDATE_PDN_CONNECTION_SET_RESPONSE:
  case GTP_MODIFY_ACCESS_BEARERS_REQUEST:
  case GTP_MODIFY_ACCESS_BEARERS_RESPONSE:
  case GTP_MBMS_SESSION_START_REQUEST:
  case GTP_MBMS_SESSION_START_RESPONSE:
  case GTP_MBMS_SESSION_UPDATE_REQUEST:
  case GTP_MBMS_SESSION_UPDATE_RESPONSE:
  case GTP_MBMS_SESSION_STOP_RESPONSE:
    break;
  default:
    Logger::mme_s11().error( "handle_receive_gtpv2c_msg msg length %d", msg.get_message_length());
  }
}
//------------------------------------------------------------------------------
void mme_s11::handle_receive(char* recv_buffer, const std::size_t bytes_transferred, boost::asio::ip::udp::endpoint& remote_endpoint)
{
  Logger::mme_s11().info( "handle_receive(%d bytes)", bytes_transferred);
  std::istringstream iss(std::istringstream::binary);
  iss.rdbuf()->pubsetbuf(recv_buffer,bytes_transferred);
  gtpv2c_msg msg = {};
  msg.remote_port = remote_endpoint.port();
  try {
    msg.load_from(iss);
    handle_receive_gtpv2c_msg(msg, remote_endpoint);
  } catch (gtpc_exception& e) {
    Logger::mme_s11().info( "handle_receive exception %s", e.what());
  }
}
//------------------------------------------------------------------------------
void mme_s11::time_out_itti_event(const uint32_t timer_id)
{
  if (start_timer == timer_id) {
    Logger::mme_s11().info( "Start autotests");
    mme_s11_inst->send_create_session_request();
  } else {
    bool handled = false;
    time_out_event(timer_id, TASK_MME_S11, handled);
    if (!handled) {
      Logger::sgwc_s11().error( "Timer %d not Found", timer_id);
    }
  }
}

//------------------------------------------------------------------------------
void mme_s11::send_create_session_request()
{
  gtpv2c_create_session_request csr = {};

  msisdn_t msisdn = {};
  msisdn.u1.digits.digit1 = 3;
  msisdn.u1.digits.digit2 = 3;
  msisdn.u1.digits.digit3 = 6;
  msisdn.u1.digits.digit4 = 1;
  msisdn.u1.digits.digit5 = 2;
  msisdn.u1.digits.digit6 = 3;
  msisdn.u1.digits.digit7 = 4;
  msisdn.u1.digits.digit8 = 5;
  msisdn.u1.digits.digit9 = 6;
  msisdn.u1.digits.digit10 = 7;
  msisdn.u1.digits.digit11 = 8;
  msisdn.u1.digits.digit12 = 9;
  msisdn.u1.digits.digit13 = 9;
  msisdn.u1.digits.digit14 = 9;
  msisdn.u1.digits.digit15 = 9;
  msisdn.num_digits = 11;

  mei_t mei = {};
  mei.u1.digits.digit1 = 0;
  mei.u1.digits.digit2 = 9;
  mei.u1.digits.digit3 = 1;
  mei.u1.digits.digit4 = 8;
  mei.u1.digits.digit5 = 2;
  mei.u1.digits.digit6 = 7;
  mei.u1.digits.digit7 = 3;
  mei.u1.digits.digit8 = 6;
  mei.u1.digits.digit9 = 4;
  mei.u1.digits.digit10 = 5;
  mei.u1.digits.digit11 = 5;
  mei.u1.digits.digit12 = 4;
  mei.u1.digits.digit13 = 6;
  mei.u1.digits.digit14 = 3;
  mei.u1.digits.digit15 = 7;
  mei.u1.digits.filler = 2;
  mei.num_digits = 16;

  uli_t uli = {};
  uli.user_location_information_ie_hdr.tai = 1;
  uli.tai1.mcc_digit_1 = 2;
  uli.tai1.mcc_digit_2 = 0;
  uli.tai1.mcc_digit_3 = 8;
  uli.tai1.mnc_digit_1 = 9;
  uli.tai1.mnc_digit_2 = 3;
  uli.tai1.mnc_digit_3 = 0xF;
  uli.tai1.tracking_area_code = 0x12;

  serving_network_t sn = {};
  sn.mcc_digit_1 = 2;
  sn.mcc_digit_2 = 0;
  sn.mcc_digit_3 = 8;
  sn.mnc_digit_1 = 9;
  sn.mnc_digit_2 = 3;
  sn.mnc_digit_3 = 0xF;

  rat_type_t rt = {};
  rt.rat_type = RAT_TYPE_E_EUTRAN_WB_EUTRAN;

  indication_t indication_flags = {};
  indication_flags.aopi = 1;

  sender_fteid_for_cp.interface_type = S11_MME_GTP_C;
  sender_fteid_for_cp.v4 = 1;
  sender_fteid_for_cp.ipv4_address = sgwc_cfg.s11_cp.addr4;
  sender_fteid_for_cp.teid_gre_key = generate_s11_cp_teid();

  fteid_t pgw_s5s8_address_for_cp = {};
  pgw_s5s8_address_for_cp.interface_type = S5_S8_PGW_GTP_C;
  pgw_s5s8_address_for_cp.v4 = 1;
  pgw_s5s8_address_for_cp.ipv4_address = pgw_cfg.s5s8_cp.addr4;
  pgw_s5s8_address_for_cp.teid_gre_key = 0;

  apn_t apn = {};
  apn.access_point_name = pgw_cfg.apn[0].apn;

  selection_mode_t sm = {};
  sm.selec_mode = SELECTION_MODE_E_MS_OR_NETWORK_PROVIDED_APN_SUBSCRIPTION_VERIFIED;

  pdn_type_t pdn_type = {};
  pdn_type.pdn_type = PDN_TYPE_E_IPV4;

  paa_t paa = {};
  paa.pdn_type.pdn_type = PDN_TYPE_E_IPV4;
  paa.ipv4_address.s_addr = INADDR_ANY;


  core::protocol_configuration_options_t pco = {};
  pco.ext = 1;
  pco.spare = 0;
  pco.configuration_protocol = PCO_CONFIGURATION_PROTOCOL_PPP_FOR_USE_WITH_IP_PDP_TYPE_OR_IP_PDN_TYPE;
  pco.num_protocol_or_container_id = 0;

  pco.protocol_or_container_ids[pco.num_protocol_or_container_id].protocol_id = PCO_PROTOCOL_IDENTIFIER_IPCP;
  uint8_t pco_content[] = {0x01, 0x00, 0x00, 0x1c, 0x81, 0x06, 0x00, 0x00, 0x00, 0x00, 0x82, 0x06, 0x00, 0x00, 0x00, 0x00, 0x83, 0x06, 0x00, 0x00, 0x00, 0x00, 0x84, 0x06, 0x00, 0x00, 0x00, 0x00 };
  std::string pco_content_s((const char*)&pco_content[0],sizeof(pco_content));
  pco.protocol_or_container_ids[pco.num_protocol_or_container_id].length_of_protocol_id_contents = sizeof(pco_content);
  pco.protocol_or_container_ids[pco.num_protocol_or_container_id].protocol_id_contents = pco_content_s;
  pco.num_protocol_or_container_id++;

  pco.protocol_or_container_ids[pco.num_protocol_or_container_id].protocol_id = PCO_CONTAINER_IDENTIFIER_DNS_SERVER_IPV4_ADDRESS_REQUEST;
  pco.protocol_or_container_ids[pco.num_protocol_or_container_id].length_of_protocol_id_contents = 4;
  std::string tmp_s(4,0);
  pco.protocol_or_container_ids[pco.num_protocol_or_container_id].protocol_id_contents = tmp_s;
  pco.num_protocol_or_container_id++;


  apn_restriction_t maximum_apn_restriction = {};
  maximum_apn_restriction.restriction_type_value = 2;

  ambr_t apn_ambr = {};
  apn_ambr.br_dl = 987654;
  apn_ambr.br_ul = 456789;

  bearer_context_to_be_created_within_create_session_request bctbc = {};
  bearer_qos_t bq = {};
  bq.guaranted_bit_rate_for_downlink = 0;
  bq.guaranted_bit_rate_for_uplink = 0;
  bq.label_qci = 9;
  bq.maximum_bit_rate_for_downlink = 654321;
  bq.maximum_bit_rate_for_uplink = 123456;
  bq.pci = 1;
  bq.pvi = 1;
  bq.pl = 1;
  bctbc.set(bq);
  ebi_t ebi = {};
  ebi.ebi = 5;
  bctbc.set(ebi);

  ue_time_zone_t uetz = {};
  uetz.time_zone = 1;
  uetz.daylight_saving_time = 2;

  csr.set(imsi);
  csr.set(msisdn);
  csr.set(mei);
  csr.set(uli);
  csr.set(sn);
  csr.set(rt);
  csr.set(indication_flags);
  csr.set_sender_fteid_for_cp(sender_fteid_for_cp);
  csr.set_pgw_s5s8_address_for_cp(pgw_s5s8_address_for_cp);
  csr.set(apn);
  csr.set(sm);
  csr.set(pdn_type);
  csr.set(paa);
  csr.set(maximum_apn_restriction);
  csr.set(apn_ambr);
  csr.set(pco);
  csr.add_bearer_context_to_be_created(bctbc);
  csr.set(uetz);

  send_initial_message(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(ntohl(sgwc_cfg.s11_cp.addr4.s_addr)), sgwc_cfg.s11_cp.port), 0x0, csr, TASK_MME_S11, generate_gtpc_tx_id());

}
//------------------------------------------------------------------------------
void mme_s11::send_modify_bearer_request(teid_t teid)
{
  gtpv2c_modify_bearer_request mbr = {};

  bearer_context_to_be_modified_within_modify_bearer_request bctbm = {};
  ebi_t ebi = {};
  ebi.ebi = 5;
  bctbm.set(ebi);

  core::fteid_t                  s1_u_enb_fteid = {};
  s1_u_enb_fteid.interface_type = S1_U_ENODEB_GTP_U;
  s1_u_enb_fteid.v4 = 1;
  s1_u_enb_fteid.ipv4_address = sgwc_cfg.s11_cp.addr4;
  s1_u_enb_fteid.teid_gre_key = teid+10; // ...!

  bctbm.set_s1_u_enb_fteid(s1_u_enb_fteid);

  mbr.add_bearer_context_to_be_modified(bctbm);

  send_initial_message(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(ntohl(sgwc_cfg.s11_cp.addr4.s_addr)), sgwc_cfg.s11_cp.port), teid, mbr, TASK_MME_S11, generate_gtpc_tx_id());

}
//------------------------------------------------------------------------------
void mme_s11::send_delete_session_request(teid_t teid)
{
  gtpv2c_delete_session_request dsr = {};


  uli_t uli = {};
  uli.user_location_information_ie_hdr.tai = 1;
  uli.tai1.mcc_digit_1 = 2;
  uli.tai1.mcc_digit_2 = 0;
  uli.tai1.mcc_digit_3 = 8;
  uli.tai1.mnc_digit_1 = 9;
  uli.tai1.mnc_digit_2 = 3;
  uli.tai1.mnc_digit_3 = 0xF;
  uli.tai1.tracking_area_code = 0x12;


  indication_t indication_flags = {};
  indication_flags.oi = 1;

  ebi_t ebi = {};
  ebi.ebi = 5;

  dsr.set(uli);
  dsr.set(indication_flags);
  dsr.set(ebi);

  send_initial_message(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(ntohl(sgwc_cfg.s11_cp.addr4.s_addr)), sgwc_cfg.s11_cp.port), teid, dsr, TASK_MME_S11, generate_gtpc_tx_id());

}

