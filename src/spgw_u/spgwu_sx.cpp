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

/*! \file spgwu_sx.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "spgwu_config.hpp"
#include "spgwu_sx.hpp"

#include <stdexcept>

using namespace oai::cn::core;
using namespace oai::cn::proto::pfcp;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::spgwu;
using namespace std;

extern itti_mw *itti_inst;
extern spgwu_config spgwu_cfg;
extern spgwu_sx  *spgwu_sx_inst;

void spgwu_sx_task (void*);

//------------------------------------------------------------------------------

void spgwu_sx_task (void *args_p)
{
  const task_id_t task_id = TASK_SPGWU_SX;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {
    case SXAB_HEARTBEAT_REQUEST:
      if (itti_sxab_heartbeat_request* m = dynamic_cast<itti_sxab_heartbeat_request*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_HEARTBEAT_RESPONSE:
      if (itti_sxab_heartbeat_response* m = dynamic_cast<itti_sxab_heartbeat_response*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_SETUP_REQUEST:
      if (itti_sxab_association_setup_request* m = dynamic_cast<itti_sxab_association_setup_request*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_SETUP_RESPONSE:
      if (itti_sxab_association_setup_response* m = dynamic_cast<itti_sxab_association_setup_response*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_UPDATE_REQUEST:
      if (itti_sxab_association_update_request* m = dynamic_cast<itti_sxab_association_update_request*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_UPDATE_RESPONSE:
      if (itti_sxab_association_update_response* m = dynamic_cast<itti_sxab_association_update_response*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_RELEASE_REQUEST:
      if (itti_sxab_association_release_request* m = dynamic_cast<itti_sxab_association_release_request*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_ASSOCIATION_RELEASE_RESPONSE:
      if (itti_sxab_association_release_response* m = dynamic_cast<itti_sxab_association_release_response*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_VERSION_NOT_SUPPORTED_RESPONSE:
      if (itti_sxab_version_not_supported_response* m = dynamic_cast<itti_sxab_version_not_supported_response*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_NODE_REPORT_RESPONSE:
      if (itti_sxab_node_report_response* m = dynamic_cast<itti_sxab_node_report_response*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_SET_DELETION_REQUEST:
      if (itti_sxab_session_set_deletion_request* m = dynamic_cast<itti_sxab_session_set_deletion_request*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_ESTABLISHMENT_REQUEST:
      if (itti_sxab_session_establishment_request* m = dynamic_cast<itti_sxab_session_establishment_request*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_MODIFICATION_REQUEST:
      if (itti_sxab_session_modification_request* m = dynamic_cast<itti_sxab_session_modification_request*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_DELETION_REQUEST:
      if (itti_sxab_session_deletion_request* m = dynamic_cast<itti_sxab_session_deletion_request*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case SXAB_SESSION_REPORT_RESPONSE:
      if (itti_sxab_session_report_response* m = dynamic_cast<itti_sxab_session_report_response*>(msg)) {
        spgwu_sx_inst->handle_itti_msg(ref(*m));
      }
      break;

    case TIME_OUT:
      if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
        Logger::spgwu_sx().info( "TIME-OUT event timer id %d", to->timer_id);
      }
      break;
    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::spgwu_sx().info( "Received terminate message");
        return;
      }
      break;
    default:
      Logger::spgwu_sx().info( "no handler for msg type %d", msg->msg_type);
    }

  } while (true);
}

//------------------------------------------------------------------------------
spgwu_sx::spgwu_sx ()
{
  Logger::spgwu_sx().startup("Starting...");
  if (itti_inst->create_task(TASK_SPGWU_SX, spgwu_sx_task, nullptr) ) {
    Logger::spgwu_sx().error( "Cannot create task TASK_SPGWU_SX" );
    throw std::runtime_error( "Cannot create task TASK_SPGWU_SX" );
  }
  Logger::spgwu_sx().startup( "Started" );
}

