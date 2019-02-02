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

/*! \file pgwc_sxab.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "pgw_config.hpp"
#include "pgwc_sxab.hpp"

#include <stdexcept>

using namespace oai::cn::core;
using namespace oai::cn::proto::pfcp;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::pgwc;
using namespace std;

extern itti_mw *itti_inst;
extern pgw_config pgw_cfg;
extern pgwc_sxab  *pgwc_sxab_inst;

void pgwc_sxab_task (void*);

//------------------------------------------------------------------------------

void pgwc_sxab_task (void *args_p)
{
  const task_id_t task_id = TASK_PGWC_SX;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {
    case SXAB_HEARTBEAT_REQUEST:
      if (itti_sxab_heartbeat_request* m = dynamic_cast<itti_sxab_heartbeat_request*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_HEARTBEAT_RESPONSE:
      if (itti_sxab_heartbeat_response* m = dynamic_cast<itti_sxab_heartbeat_response*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_SETUP_REQUEST:
      if (itti_sxab_association_setup_request* m = dynamic_cast<itti_sxab_association_setup_request*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_SETUP_RESPONSE:
      if (itti_sxab_association_setup_response* m = dynamic_cast<itti_sxab_association_setup_response*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_UPDATE_REQUEST:
      if (itti_sxab_association_update_request* m = dynamic_cast<itti_sxab_association_update_request*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_UPDATE_RESPONSE:
      if (itti_sxab_association_update_response* m = dynamic_cast<itti_sxab_association_update_response*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_RELEASE_REQUEST:
      if (itti_sxab_association_release_request* m = dynamic_cast<itti_sxab_association_release_request*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_RELEASE_RESPONSE:
      if (itti_sxab_association_release_response* m = dynamic_cast<itti_sxab_association_release_response*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_VERSION_NOT_SUPPORTED_RESPONSE:
      if (itti_sxab_version_not_supported_response* m = dynamic_cast<itti_sxab_version_not_supported_response*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_NODE_REPORT_RESPONSE:
      if (itti_sxab_node_report_response* m = dynamic_cast<itti_sxab_node_report_response*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_SET_DELETION_REQUEST:
      if (itti_sxab_session_set_deletion_request* m = dynamic_cast<itti_sxab_session_set_deletion_request*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_ESTABLISHMENT_REQUEST:
      if (itti_sxab_session_establishment_request* m = dynamic_cast<itti_sxab_session_establishment_request*>(msg)) {
        pgwc_sxab_inst->send_sx_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_MODIFICATION_REQUEST:
      if (itti_sxab_session_modification_request* m = dynamic_cast<itti_sxab_session_modification_request*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_DELETION_REQUEST:
      if (itti_sxab_session_deletion_request* m = dynamic_cast<itti_sxab_session_deletion_request*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_REPORT_RESPONSE:
      if (itti_sxab_session_report_response* m = dynamic_cast<itti_sxab_session_report_response*>(msg)) {
        pgwc_sxab_inst->handle_itti_msg(ref(*m));
      }
      break;

    case TIME_OUT:
      if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
        Logger::pgwc_sx().info( "TIME-OUT event timer id %d", to->timer_id);
      }
      break;
    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::pgwc_sx().info( "Received terminate message");
        return;
      }
      break;
    default:
      Logger::pgwc_sx().info( "no handler for msg type %d", msg->msg_type);
    }

  } while (true);
}

//------------------------------------------------------------------------------
pgwc_sxab::pgwc_sxab() : pfcp_l4_stack(string(inet_ntoa(pgw_cfg.sx.addr4)), pgw_cfg.sx.port)
{
  Logger::pgwc_sx().startup("Starting...");
  if (itti_inst->create_task(TASK_PGWC_SX, pgwc_sxab_task, nullptr) ) {
    Logger::pgwc_sx().error( "Cannot create task TASK_PGWC_SX" );
    throw std::runtime_error( "Cannot create task TASK_PGWC_SX" );
  }
  Logger::pgwc_sx().startup( "Started" );
}
//------------------------------------------------------------------------------
void pgwc_sxab::handle_receive_pfcp_msg(pfcp_msg& msg, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
  Logger::pgwc_sx().trace( "handle_receive_pfcp_msg msg type %d length %d", msg.get_message_type(), msg.get_message_length());
  switch (msg.get_message_type()) {

  case PFCP_HEARTBEAT_REQUEST:
    //handle_receive_create_session_request(msg, remote_endpoint);
    break;
  case PFCP_HEARTBEAT_RESPONSE:
    break;
  case PFCP_PFCP_PFD_MANAGEMENT_REQUEST:
  case PFCP_PFCP_PFD_MANAGEMENT_RESPONSE:
  case PFCP_ASSOCIATION_SETUP_REQUEST:
  case PFCP_ASSOCIATION_SETUP_RESPONSE:
  case PFCP_ASSOCIATION_UPDATE_REQUEST:
  case PFCP_ASSOCIATION_UPDATE_RESPONSE:
  case PFCP_ASSOCIATION_RELEASE_REQUEST:
  case PFCP_ASSOCIATION_RELEASE_RESPONSE:
  case PFCP_VERSION_NOT_SUPPORTED_RESPONSE:
  case PFCP_NODE_REPORT_REQUEST:
  case PFCP_NODE_REPORT_RESPONSE:
  case PFCP_SESSION_SET_DELETION_REQUEST:
  case PFCP_SESSION_SET_DELETION_RESPONSE:
  case PFCP_SESSION_ESTABLISHMENT_REQUEST:
  case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
  case PFCP_SESSION_MODIFICATION_REQUEST:
  case PFCP_SESSION_MODIFICATION_RESPONSE:
  case PFCP_SESSION_DELETION_REQUEST:
  case PFCP_SESSION_DELETION_RESPONSE:
  case PFCP_SESSION_REPORT_REQUEST:
  case PFCP_SESSION_REPORT_RESPONSE:
    Logger::pgwc_sx().info( "handle_receive_pfcp_msg msg %d length %d, not handled, discarded!", msg.get_message_type(), msg.get_message_length());
    break;
  default:
    Logger::pgwc_sx().info( "handle_receive_pfcp_msg msg %d length %d, unknown, discarded!", msg.get_message_type(), msg.get_message_length());
  }
}

////------------------------------------------------------------------------------
//// used only if ITTI messaging is used between SGW and PGW
//void pgwc_sxab::handle_itti_msg (itti_s5s8_create_session_response& csreq)
//{
//  itti_s5s8_create_session_response csr(csreq, TASK_SGWC_S5S8, TASK_SGWC_APP);
//
//  std::shared_ptr<itti_s5s8_create_session_response> msg = std::make_shared<itti_s5s8_create_session_response>(csr);
//  int ret = itti_inst->send_msg(msg);
//  if (RETURNok != ret) {
//    Logger::pgwc_s5s8().error( "Could not send ITTI message %s to task TASK_SGWC_APP", csr.get_msg_name());
//  }
//}
//------------------------------------------------------------------------------
void pgwc_sxab::send_sx_msg(itti_sxab_session_establishment_request& i)
{
  send_request(i.r_endpoint, i.seid, i.pfcp_ies, TASK_PGWC_SX, i.trxn_id);
}
//------------------------------------------------------------------------------
void pgwc_sxab::handle_receive(char* recv_buffer, const std::size_t bytes_transferred, boost::asio::ip::udp::endpoint& remote_endpoint)
{
  Logger::pgwc_sx().info( "handle_receive(%d bytes)", bytes_transferred);
  //std::cout << string_to_hex(recv_buffer, bytes_transferred) << std::endl;
  std::istringstream iss(std::istringstream::binary);
  iss.rdbuf()->pubsetbuf(recv_buffer,bytes_transferred);
  pfcp_msg msg = {};
  msg.remote_port = remote_endpoint.port();
  try {
    msg.load_from(iss);
    handle_receive_pfcp_msg(msg, remote_endpoint);
  } catch (pfcp_exception& e) {
    Logger::pgwc_sx().info( "handle_receive exception %s", e.what());
  }
}
//------------------------------------------------------------------------------
void pgwc_sxab::time_out_itti_event(const uint32_t timer_id)
{
  bool handled = false;
  time_out_event(timer_id, TASK_PGWC_SX, handled);
  if (!handled) {
    Logger::pgwc_sx().error( "Timer %d not Found", timer_id);
  }
}


