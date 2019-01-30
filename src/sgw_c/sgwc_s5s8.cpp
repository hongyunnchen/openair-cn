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

/*! \file sgw_s5s8.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "sgwc_config.hpp"
#include "sgwc_s5s8.hpp"

#include <stdexcept>

using namespace oai::cn::core;
using namespace oai::cn::proto::gtpv2c;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::sgwc;
using namespace std;

extern itti_mw *itti_inst;
extern sgwc_config sgwc_cfg;
extern sgw_s5s8  *sgw_s5s8_inst;

void sgw_s5s8_task (void*);

//------------------------------------------------------------------------------

void sgw_s5s8_task (void *args_p)
{
  const task_id_t task_id = TASK_SGWC_S5S8;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {
    case S5S8_CREATE_SESSION_REQUEST:
      if (itti_s5s8_create_session_request* m = dynamic_cast<itti_s5s8_create_session_request*>(msg)) {
        itti_s5s8_create_session_request csr(ref(*m));
        csr.origin = task_id;
        csr.destination = TASK_PGWC_S5S8;
        std::shared_ptr<itti_s5s8_create_session_request> msg = std::make_shared<itti_s5s8_create_session_request>(csr);
        int ret = itti_inst->send_msg(msg);
        if (RETURNok != ret) {
          Logger::sgwc_s5s8().error( "Could not send ITTI message %s to task TASK_PGWC_S5S8", csr.get_msg_name());
        }
      }
      break;
    case S5S8_MODIFY_BEARER_REQUEST:
      if (itti_s5s8_modify_bearer_request* m = dynamic_cast<itti_s5s8_modify_bearer_request*>(msg)) {
        itti_s5s8_modify_bearer_request csr(ref(*m));
        csr.origin = task_id;
        csr.destination = TASK_PGWC_S5S8;
        std::shared_ptr<itti_s5s8_modify_bearer_request> msg = std::make_shared<itti_s5s8_modify_bearer_request>(csr);
        int ret = itti_inst->send_msg(msg);
        if (RETURNok != ret) {
          Logger::sgwc_s5s8().error( "Could not send ITTI message %s to task TASK_PGWC_S5S8", csr.get_msg_name());
        }
      }
      break;
    case S5S8_DELETE_SESSION_REQUEST:
      if (itti_s5s8_delete_session_request* m = dynamic_cast<itti_s5s8_delete_session_request*>(msg)) {
        itti_s5s8_delete_session_request csr(ref(*m));
        csr.origin = task_id;
        csr.destination = TASK_PGWC_S5S8;
        std::shared_ptr<itti_s5s8_delete_session_request> msg = std::make_shared<itti_s5s8_delete_session_request>(csr);
        int ret = itti_inst->send_msg(msg);
        if (RETURNok != ret) {
          Logger::sgwc_s5s8().error( "Could not send ITTI message %s to task TASK_PGWC_S5S8", csr.get_msg_name());
        }
      }
      break;
    case S5S8_CREATE_SESSION_RESPONSE:
      if (itti_s5s8_create_session_response* m = dynamic_cast<itti_s5s8_create_session_response*>(msg)) {
        sgw_s5s8_inst->handle_itti_msg(ref(*m));
      }
      break;
    case S5S8_DELETE_SESSION_RESPONSE:
      if (itti_s5s8_delete_session_response* m = dynamic_cast<itti_s5s8_delete_session_response*>(msg)) {
        sgw_s5s8_inst->handle_itti_msg(ref(*m));
      }
      break;
    case S5S8_MODIFY_BEARER_RESPONSE:
      if (itti_s5s8_modify_bearer_response* m = dynamic_cast<itti_s5s8_modify_bearer_response*>(msg)) {
        sgw_s5s8_inst->handle_itti_msg(ref(*m));
      }
      break;

    case TIME_OUT:
      if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
        Logger::sgwc_s5s8().info( "TIME-OUT event timer id %d", to->timer_id);
      }
      break;
    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::sgwc_s5s8().info( "Received terminate message");
        return;
      }
      break;
    default:
      Logger::sgwc_s5s8().info( "no handler for msg type %d", msg->msg_type);
    }

  } while (true);
}

//------------------------------------------------------------------------------
sgw_s5s8::sgw_s5s8 ()
{
  Logger::sgwc_s5s8().startup("Starting...");
  if (itti_inst->create_task(TASK_SGWC_S5S8, sgw_s5s8_task, nullptr) ) {
    Logger::sgwc_s5s8().error( "Cannot create task TASK_SGWC_S5S8" );
    throw std::runtime_error( "Cannot create task TASK_SGWC_S5S8" );
  }
  Logger::sgwc_s5s8().startup( "Started" );
}

//------------------------------------------------------------------------------
// used only if ITTI messaging is used between SGW and PGW
void sgw_s5s8::handle_itti_msg (itti_s5s8_create_session_response& csreq)
{
  itti_s5s8_create_session_response csr(csreq, TASK_SGWC_S5S8, TASK_SGWC_APP);

  std::shared_ptr<itti_s5s8_create_session_response> msg = std::make_shared<itti_s5s8_create_session_response>(csr);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::pgwc_s5s8().error( "Could not send ITTI message %s to task TASK_SGWC_APP", csr.get_msg_name());
  }
}
//------------------------------------------------------------------------------
void sgw_s5s8::handle_itti_msg (itti_s5s8_delete_session_response& dsreq)
{
  itti_s5s8_delete_session_response dsr(dsreq, TASK_SGWC_S5S8, TASK_SGWC_APP);

  std::shared_ptr<itti_s5s8_delete_session_response> msg = std::make_shared<itti_s5s8_delete_session_response>(dsr);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::pgwc_s5s8().error( "Could not send ITTI message %s to task TASK_SGWC_APP", dsr.get_msg_name());
  }
}
//------------------------------------------------------------------------------
void sgw_s5s8::handle_itti_msg (itti_s5s8_modify_bearer_response& mbreq)
{
  itti_s5s8_modify_bearer_response mbr(mbreq, TASK_SGWC_S5S8, TASK_SGWC_APP);

  std::shared_ptr<itti_s5s8_modify_bearer_response> msg = std::make_shared<itti_s5s8_modify_bearer_response>(mbr);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::pgwc_s5s8().error( "Could not send ITTI message %s to task TASK_SGWC_APP", mbr.get_msg_name());
  }
}
//------------------------------------------------------------------------------
void sgw_s5s8::send_s5s8_msg(itti_s5s8_create_session_request& i)
{
  i.origin = TASK_SGWC_S5S8;
  i.destination = TASK_PGWC_S5S8;

  std::shared_ptr<itti_s5s8_create_session_request> msg = std::make_shared<itti_s5s8_create_session_request>(i);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::sgwc_s11().error( "Could not send ITTI message %s to task TASK_PGWC_S5S8", i.get_msg_name());
  }
}
//------------------------------------------------------------------------------
void sgw_s5s8::send_s5s8_msg(itti_s5s8_delete_session_request& i)
{
  i.origin = TASK_SGWC_S5S8;
  i.destination = TASK_PGWC_S5S8;

  std::shared_ptr<itti_s5s8_delete_session_request> msg = std::make_shared<itti_s5s8_delete_session_request>(i);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::sgwc_s11().error( "Could not send ITTI message %s to task TASK_PGWC_S5S8", i.get_msg_name());
  }
}
//------------------------------------------------------------------------------
void sgw_s5s8::send_s5s8_msg(itti_s5s8_modify_bearer_request& i)
{
  i.origin = TASK_SGWC_S5S8;
  i.destination = TASK_PGWC_S5S8;

  std::shared_ptr<itti_s5s8_modify_bearer_request> msg = std::make_shared<itti_s5s8_modify_bearer_request>(i);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::sgwc_s11().error( "Could not send ITTI message %s to task TASK_PGWC_S5S8", i.get_msg_name());
  }
}
