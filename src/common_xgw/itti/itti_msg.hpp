/*
 * itti_msg.hpp
 *
 *  Created on: Oct 6, 2018
 *      Author: lionel.gauthier@eurecom.fr
 */

#ifndef SRC_OAI_SGW_COMMON_ITTI_ITTI_MSG_H_INCLUDED_
#define SRC_OAI_SGW_COMMON_ITTI_ITTI_MSG_H_INCLUDED_

#include <stdint.h>
#include <typeinfo>
#include <iostream>

namespace oai::cn::core::itti {

typedef enum {
  TASK_FIRST = 0,
  TASK_ITTI_TIMER = TASK_FIRST,
  TASK_ASYNC_SHELL_CMD,
  TASK_GTPV1_U,
  TASK_GTPV2_C,
  TASK_MME_S11,
  TASK_PGWC_APP,
  TASK_PGWU_APP,
  TASK_SPGWU_APP,
  TASK_PGWC_S5S8,
  TASK_PGWC_SXB,
  TASK_PGWU_SXB,
  TASK_PGW_UDP,
  TASK_SGWC_APP,
  TASK_SGWU_APP,
  TASK_SGWC_S11,
  TASK_SGWC_S5S8,
  TASK_SGWC_SXA,
  TASK_SGWU_SXA,
  TASK_SPGWU_SX,
  TASK_SGW_UDP,
  TASK_MAX,
  TASK_NONE,
  TASK_ALL = 255
} task_id_t;

typedef enum message_priorities_e {
  MESSAGE_PRIORITY_MAX       = 100,
  MESSAGE_PRIORITY_MAX_LEAST = 85,
  MESSAGE_PRIORITY_MED_PLUS  = 70,
  MESSAGE_PRIORITY_MED       = 55,
  MESSAGE_PRIORITY_MED_LEAST = 40,
  MESSAGE_PRIORITY_MIN_PLUS  = 25,
  MESSAGE_PRIORITY_MIN       = 10,
} message_priorities_t;

typedef enum {
  ITTI_MSG_TYPE_NONE = -1,
  ITTI_MSG_TYPE_FIRST = 0,
  ASYNC_SHELL_CMD = ITTI_MSG_TYPE_FIRST,
  GTPV1U_CREATE_TUNNEL_REQ,
  GTPV1U_CREATE_TUNNEL_RESP,
  GTPV1U_UPDATE_TUNNEL_REQ,
  GTPV1U_UPDATE_TUNNEL_RESP,
  GTPV1U_DELETE_TUNNEL_REQ,
  GTPV1U_DELETE_TUNNEL_RESP,
  GTPV1U_TUNNEL_DATA_IND,
  GTPV1U_TUNNEL_DATA_REQ,
  GTPV1U_DOWNLINK_DATA_NOTIFICATION,
  S11_CREATE_SESSION_REQUEST,
  S11_CREATE_SESSION_RESPONSE,
  S11_CREATE_BEARER_REQUEST,
  S11_CREATE_BEARER_RESPONSE,
  S11_MODIFY_BEARER_REQUEST,
  S11_MODIFY_BEARER_RESPONSE,
  S11_DELETE_BEARER_COMMAND,
  S11_DELETE_BEARER_FAILURE_INDICATION,
  S11_DELETE_SESSION_REQUEST,
  S11_DELETE_SESSION_RESPONSE,
  S11_RELEASE_ACCESS_BEARERS_REQUEST,
  S11_RELEASE_ACCESS_BEARERS_RESPONSE,
  S11_DOWNLINK_DATA_NOTIFICATION,
  S11_DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE,
  S11_DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION,
  S5S8_CREATE_SESSION_REQUEST,
  S5S8_CREATE_SESSION_RESPONSE,
  S5S8_CREATE_BEARER_REQUEST,
  S5S8_CREATE_BEARER_RESPONSE,
  S5S8_MODIFY_BEARER_REQUEST,
  S5S8_MODIFY_BEARER_RESPONSE,
  S5S8_DELETE_BEARER_COMMAND,
  S5S8_DELETE_BEARER_FAILURE_INDICATION,
  S5S8_DELETE_SESSION_REQUEST,
  S5S8_DELETE_SESSION_RESPONSE,
  S5S8_RELEASE_ACCESS_BEARERS_REQUEST,
  S5S8_RELEASE_ACCESS_BEARERS_RESPONSE,
  SXA_HEARTBEAT_REQUEST,
  SXA_HEARTBEAT_RESPONSE,
  SXA_ASSOCIATION_SETUP_REQUEST,
  SXA_ASSOCIATION_SETUP_RESPONSE,
  SXA_ASSOCIATION_UPDATE_REQUEST,
  SXA_ASSOCIATION_UPDATE_RESPONSE,
  SXA_ASSOCIATION_RELEASE_REQUEST,
  SXA_ASSOCIATION_RELEASE_RESPONSE,
  SXA_VERSION_NOT_SUPPORTED_RESPONSE,
  SXA_NODE_REPORT_REQUEST,
  SXA_NODE_REPORT_RESPONSE,
  SXA_SESSION_SET_DELETION_REQUEST,
  SXA_SESSION_SET_DELETION_RESPONSE,
  SXA_SESSION_ESTABLISHMENT_REQUEST,
  SXA_SESSION_ESTABLISHMENT_RESPONSE,
  SXA_SESSION_MODIFICATION_REQUEST,
  SXA_SESSION_MODIFICATION_RESPONSE,
  SXA_SESSION_DELETION_REQUEST,
  SXA_SESSION_DELETION_RESPONSE,
  SXA_SESSION_REPORT_REQUEST,
  SXA_SESSION_REPORT_RESPONSE,
  SXB_HEARTBEAT_REQUEST,
  SXB_HEARTBEAT_RESPONSE,
  SXB_PFCP_PFD_MANAGEMENT_REQUEST,
  SXB_PFCP_PFD_MANAGEMENT_RESPONSE,
  SXB_ASSOCIATION_SETUP_REQUEST,
  SXB_ASSOCIATION_SETUP_RESPONSE,
  SXB_ASSOCIATION_UPDATE_REQUEST,
  SXB_ASSOCIATION_UPDATE_RESPONSE,
  SXB_ASSOCIATION_RELEASE_REQUEST,
  SXB_ASSOCIATION_RELEASE_RESPONSE,
  SXB_VERSION_NOT_SUPPORTED_RESPONSE,
  SXB_NODE_REPORT_REQUEST,
  SXB_NODE_REPORT_RESPONSE,
  SXB_SESSION_SET_DELETION_REQUEST,
  SXB_SESSION_SET_DELETION_RESPONSE,
  SXB_SESSION_ESTABLISHMENT_REQUEST,
  SXB_SESSION_ESTABLISHMENT_RESPONSE,
  SXB_SESSION_MODIFICATION_REQUEST,
  SXB_SESSION_MODIFICATION_RESPONSE,
  SXB_SESSION_DELETION_REQUEST,
  SXB_SESSION_DELETION_RESPONSE,
  SXB_SESSION_REPORT_REQUEST,
  SXB_SESSION_REPORT_RESPONSE,
  SXAB_HEARTBEAT_REQUEST,
  SXAB_HEARTBEAT_RESPONSE,
  SXAB_PFCP_PFD_MANAGEMENT_REQUEST,
  SXAB_PFCP_PFD_MANAGEMENT_RESPONSE,
  SXAB_ASSOCIATION_SETUP_REQUEST,
  SXAB_ASSOCIATION_SETUP_RESPONSE,
  SXAB_ASSOCIATION_UPDATE_REQUEST,
  SXAB_ASSOCIATION_UPDATE_RESPONSE,
  SXAB_ASSOCIATION_RELEASE_REQUEST,
  SXAB_ASSOCIATION_RELEASE_RESPONSE,
  SXAB_VERSION_NOT_SUPPORTED_RESPONSE,
  SXAB_NODE_REPORT_REQUEST,
  SXAB_NODE_REPORT_RESPONSE,
  SXAB_SESSION_SET_DELETION_REQUEST,
  SXAB_SESSION_SET_DELETION_RESPONSE,
  SXAB_SESSION_ESTABLISHMENT_REQUEST,
  SXAB_SESSION_ESTABLISHMENT_RESPONSE,
  SXAB_SESSION_MODIFICATION_REQUEST,
  SXAB_SESSION_MODIFICATION_RESPONSE,
  SXAB_SESSION_DELETION_REQUEST,
  SXAB_SESSION_DELETION_RESPONSE,
  SXAB_SESSION_REPORT_REQUEST,
  SXAB_SESSION_REPORT_RESPONSE,
  SXC_HEARTBEAT_REQUEST,
  SXC_HEARTBEAT_RESPONSE,
  SXC_PFCP_PFD_MANAGEMENT_REQUEST,
  SXC_PFCP_PFD_MANAGEMENT_RESPONSE,
  SXC_ASSOCIATION_SETUP_REQUEST,
  SXC_ASSOCIATION_SETUP_RESPONSE,
  SXC_ASSOCIATION_UPDATE_REQUEST,
  SXC_ASSOCIATION_UPDATE_RESPONSE,
  SXC_ASSOCIATION_RELEASE_REQUEST,
  SXC_ASSOCIATION_RELEASE_RESPONSE,
  SXC_VERSION_NOT_SUPPORTED_RESPONSE,
  SXC_NODE_REPORT_REQUEST,
  SXC_NODE_REPORT_RESPONSE,
  SXC_SESSION_ESTABLISHMENT_REQUEST,
  SXC_SESSION_ESTABLISHMENT_RESPONSE,
  SXC_SESSION_MODIFICATION_REQUEST,
  SXC_SESSION_MODIFICATION_RESPONSE,
  SXC_SESSION_DELETION_REQUEST,
  SXC_SESSION_DELETION_RESPONSE,
  SXC_SESSION_REPORT_REQUEST,
  SXC_SESSION_REPORT_RESPONSE,
  UDP_INIT,
  UDP_DATA_REQ,
  UDP_DATA_IND,
  TIME_OUT,
  HEALTH_PING,
  TERMINATE,
  ITTI_MSG_TYPE_MAX
} itti_msg_type_t;

typedef unsigned long message_number_t;

class itti_msg {
public:
  itti_msg();
  itti_msg(const itti_msg_type_t  msg_type, const task_id_t origin, const task_id_t destination);
  itti_msg(const itti_msg& i);
  virtual ~itti_msg() = default;
  const char* get_msg_name();

  message_number_t msg_num;
  task_id_t        origin;
  task_id_t        destination;
  itti_msg_type_t  msg_type;
};

class itti_msg_timeout : public itti_msg {
public:
  itti_msg_timeout(const task_id_t origin, const task_id_t destination, uint32_t timer_id): itti_msg(TIME_OUT, origin, destination), timer_id(timer_id) {}
  itti_msg_timeout(const itti_msg_timeout& i) : itti_msg(i), timer_id(i.timer_id) {}
  const char* get_msg_name() {return typeid(itti_msg_timeout).name();};
  uint32_t timer_id;
};

class itti_msg_ping : public itti_msg {
public:
  itti_msg_ping(const task_id_t origin, const task_id_t destination, uint32_t seq): itti_msg(HEALTH_PING, origin, destination), seq(seq) {}
  itti_msg_ping(const itti_msg_ping& i) : itti_msg(i), seq(i.seq) {}
  const char* get_msg_name() {return typeid(itti_msg_ping).name();};
  uint32_t seq;
};
class itti_msg_terminate : public itti_msg {
public:
  itti_msg_terminate(const task_id_t origin, const task_id_t destination):
    itti_msg(TERMINATE, origin, destination) {}
  itti_msg_terminate(const itti_msg_terminate& i) : itti_msg(i) {}
  const char* get_msg_name() {return typeid(itti_msg_terminate).name();};
};
}
#endif /* SRC_OAI_SGW_COMMON_ITTI_ITTI_MSG_H_INCLUDED_ */
