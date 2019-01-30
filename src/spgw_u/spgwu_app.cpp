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

/*! \file spgwu_app.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/
#include "conversions.h"
#include "itti.hpp"
#include "logger.hpp"
#include "spgwu_app.hpp"
#include "spgwu_config.hpp"
#include "spgwu_sx.hpp"

#include <stdexcept>

using namespace oai::cn::proto::pfcp;
using namespace oai::cn::core::itti;
using namespace oai::cn::nf::spgwu;
using namespace std;

// C includes

spgwu_sx   *spgwu_sx_inst = nullptr;

extern itti_mw *itti_inst;
extern spgwu_app *spgwu_app_inst;
extern spgwu_config spgwu_cfg;


void spgwu_app_task (void*);

//------------------------------------------------------------------------------
void spgwu_app_task (void *args_p)
{
  const task_id_t task_id = TASK_SPGWU_APP;
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
        spgwu_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S5S8_CREATE_SESSION_RESPONSE:
      if (itti_s5s8_create_session_response* m = dynamic_cast<itti_s5s8_create_session_response*>(msg)) {
        spgwu_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S11_DELETE_SESSION_REQUEST:
      if (itti_s11_delete_session_request* m = dynamic_cast<itti_s11_delete_session_request*>(msg)) {
        spgwu_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S5S8_DELETE_SESSION_RESPONSE:
      if (itti_s5s8_delete_session_response* m = dynamic_cast<itti_s5s8_delete_session_response*>(msg)) {
        spgwu_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S11_MODIFY_BEARER_REQUEST:
      if (itti_s11_modify_bearer_request* m = dynamic_cast<itti_s11_modify_bearer_request*>(msg)) {
        spgwu_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case S11_RELEASE_ACCESS_BEARERS_REQUEST:
      if (itti_s11_release_access_bearers_request* m = dynamic_cast<itti_s11_release_access_bearers_request*>(msg)) {
        spgwu_app_inst->handle_itti_msg(ref(*m));
      }
      break;

    case TIME_OUT:
      if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
        Logger::spgwu_app().info( "TIME-OUT event timer id %d", to->timer_id);
      }
      break;
    case TERMINATE:
      if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
        Logger::spgwu_app().info( "Received terminate message");
        return;
      }
      break;
    default:
      Logger::spgwu_app().info( "no handler for ITTI msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
spgwu_app::spgwu_app (const std::string& config_file) : s11lteid2sgwu_eps_bearer_context()
{
  Logger::spgwu_app().startup("Starting...");
  spgwu_cfg.load(config_file);
  spgwu_cfg.execute();
  spgwu_cfg.display();

//  teid_s11_cp = 0;
//  teid_s5s8_cp = 0;
//  teid_s5s8_up = 0;
//  imsi2sgwu_eps_bearer_context = {};
//  s11lteid2sgwu_eps_bearer_context = {};
//  s5s8lteid2sgwu_contexts = {};
//  s5s8uplteid = {};

  try {
    spgwu_sx_inst = new spgwu_sx();
  } catch (std::exception& e) {
    Logger::spgwu_app().error( "Cannot create SGW_APP: %s", e.what() );
    throw e;
  }

  if (itti_inst->create_task(TASK_SPGWU_APP, spgwu_app_task, nullptr) ) {
    Logger::spgwu_app().error( "Cannot create task TASK_SPGWU_APP" );
    throw std::runtime_error( "Cannot create task TASK_SPGWU_APP" );
  }
  Logger::spgwu_app().startup( "Started" );
}

//------------------------------------------------------------------------------
spgwu_app::~spgwu_app()
{
  if (spgwu_sx_inst) delete spgwu_sx_inst;
}


