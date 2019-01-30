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
#include "itti_msg_sxa.hpp"
#include "logger.hpp"
#include "pgw_app.hpp"
#include "pgw_config.hpp"
#include "pgwc_procedure.hpp"
#include "pgw_context.hpp"

using namespace oai::cn::core;
using namespace oai::cn::core::itti;
using namespace oai::cn::proto::pfcp;
using namespace oai::cn::nf::pgwc;
using namespace std;

extern itti_mw *itti_inst;
extern pgw_app *pgw_app_inst;
extern pgw_config pgw_cfg;

uint64_t oai::cn::nf::pgwc::pgw_procedure::tx_id_generator = 0;

//------------------------------------------------------------------------------
int session_establishment_procedure::run(shared_ptr<pgw_pdn_connection> ppc)
{

  // TODO check if compatible with ongoing procedures if any
  //for (auto p : pending_procedures) {
  //  if (p) {
  //
  //  }
  //}
  ppc.get()->generate_seid();
  itti_sxab_session_establishment_request *sx_ser = new itti_sxab_session_establishment_request(TASK_PGWC_APP, TASK_PGWC_SX);
  s5s8_csr->pfcp_tx_id = this->gtpc_tx_id;



  std::shared_ptr<itti_sxab_session_establishment_request> msg = std::shared_ptr<itti_sxab_session_establishment_request>(sx_ser);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::pgwc_app().error( "Could not send ITTI message %s to task TASK_PGWC_SX", sx_ser->get_msg_name());
    return RETURNerror;
  }
  return RETURNok;
}

