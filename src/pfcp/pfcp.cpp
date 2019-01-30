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

/*! \file gtpv2c.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "pfcp.hpp"

#include <cstdlib>

using namespace oai::cn::proto::pfcp;
using namespace oai::cn::core::itti;
using namespace std;

extern boost::asio::io_service io_service;
extern itti_mw *itti_inst;

uint64_t oai::cn::proto::pfcp::pfcp_l4_stack::pfcp_tx_id_generator = 1; //odd in any case.

static std::string string_to_hex(const std::string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}
//
////------------------------------------------------------------------------------
//void udp_server::fteid_addr2_boost_ip_address(const core::fteid_t & fteid, boost::asio::ip::address & address)
//{
//  if ((local_address_.is_v4()) && (fteid.v4)) {
//    boost::asio::ip::address_v4 addressv4(ntohl(fteid.ipv4_address.s_addr));
//    address = addressv4;
//    return;
//  }
//  if ((local_address_.is_v6()) && (fteid.v6)) {
//    boost::asio::ip::address_v6::bytes_type b;
//    for (int i = 0 ; i < 16; i++) {
//      b[i] = fteid.ipv6_address.__in6_u.__u6_addr8[i];
//    }
//    boost::asio::ip::address_v6 addressv6(b);
//    address = addressv6;
//    return;
//  }
//}
//------------------------------------------------------------------------------
void udp_server::handle_receive(const boost::system::error_code& error, std::size_t bytes_transferred)
{
  if (!error || error == boost::asio::error::message_size) {
    Logger::udp().trace( "udp_server::handle_receive on %s:%d from %s:%d",
        socket_.local_endpoint().address().to_string().c_str(), socket_.local_endpoint().port(),
        remote_endpoint_.address().to_string().c_str(), remote_endpoint_.port());
    if (app) {
      app->handle_receive(recv_buffer_.data(), bytes_transferred, remote_endpoint_);
    } else {
      Logger::udp().error( "No upper layer configured for handling UDP packet");
    }
    start_receive(app);
  } else {
    Logger::udp().error( "udp_server::handle_receive err=%s/%d: %s", error.category().name(), error.value(), error.message());
  }
}

//------------------------------------------------------------------------------
pfcp_l4_stack::pfcp_l4_stack(const string ip_address, const unsigned short port_num) :
    udp_s(udp_server(io_service, boost::asio::ip::address::from_string(ip_address), port_num)) {
  Logger::pfcp().info( "pfcp_l4_stack created listening to %s:%d", ip_address.c_str(), port_num);
  pfcp_tx_id2seq_num = {};
  proc_cleanup_timers = {};
  msg_out_retry_timers = {};
  pending_procedures = {};

  id = 0;
  srand (time(NULL));
  seq_num = rand() & 0x7FFFFFFF;
  restart_counter = 0;
  udp_s.start_receive(this);
}
//------------------------------------------------------------------------------
uint32_t pfcp_l4_stack::get_next_seq_num() {
  seq_num++;
  if (seq_num & 0x80000000) {
    seq_num = 0;
  }
  return seq_num;
}
//------------------------------------------------------------------------------
void pfcp_l4_stack::handle_receive(char* recv_buffer, const std::size_t bytes_transferred, boost::asio::ip::udp::endpoint& remote_endpoint)
{
  Logger::pfcp().error( "TODO implement in derived class");
}
//------------------------------------------------------------------------------
bool pfcp_l4_stack::check_request_type(const uint8_t initial)
{
  switch (initial) {
  case PFCP_HEARTBEAT_REQUEST:
  case PFCP_PFCP_PFD_MANAGEMENT_REQUEST:
  case PFCP_ASSOCIATION_SETUP_REQUEST:
  case PFCP_ASSOCIATION_UPDATE_REQUEST:
  case PFCP_ASSOCIATION_RELEASE_REQUEST:
  case PFCP_NODE_REPORT_REQUEST:
  case PFCP_NODE_REPORT_RESPONSE: // TODO
  case PFCP_SESSION_ESTABLISHMENT_REQUEST:
  case PFCP_SESSION_MODIFICATION_REQUEST:
  case PFCP_SESSION_DELETION_REQUEST:
  case PFCP_SESSION_REPORT_REQUEST:
  case PFCP_SESSION_REPORT_RESPONSE: // TODO
      return true;
      break;
    default:
      return false;
  }
}
//------------------------------------------------------------------------------
bool pfcp_l4_stack::check_response_type(const uint8_t initial, const uint8_t triggered)
{
  Logger::pfcp().info( "check_response_type PFCP msg type %d/%d", (int)initial, (int)triggered);
  switch (initial) {
    case PFCP_HEARTBEAT_RESPONSE:
    case PFCP_PFCP_PFD_MANAGEMENT_RESPONSE:
    case PFCP_ASSOCIATION_SETUP_RESPONSE:
    case PFCP_ASSOCIATION_UPDATE_RESPONSE:
    case PFCP_ASSOCIATION_RELEASE_RESPONSE:
    case PFCP_VERSION_NOT_SUPPORTED_RESPONSE:
    case PFCP_NODE_REPORT_RESPONSE:
    case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
    case PFCP_SESSION_MODIFICATION_RESPONSE:
    case PFCP_SESSION_DELETION_RESPONSE:
    case PFCP_SESSION_REPORT_RESPONSE:

      if (triggered == (initial+1)) return true;
      break;
    default:
      if (triggered == GTP_VERSION_NOT_SUPPORTED_INDICATION) return true;
  }
  return false;

}
//------------------------------------------------------------------------------
void pfcp_l4_stack::start_msg_retry_timer(pfcp_procedure& p, uint32_t time_out_milli_seconds, const task_id_t& task_id, const uint32_t& seq_num)
{
  p.retry_timer_id = itti_inst->timer_setup (time_out_milli_seconds/1000, time_out_milli_seconds%1000, task_id);
  msg_out_retry_timers.insert(std::pair<core::itti::timer_id_t, uint32_t>(p.retry_timer_id, seq_num));
  Logger::pfcp().trace( "Started Msg retry timer %d, proc %" PRId64", seq %d",p.retry_timer_id, p.pfcp_tx_id, seq_num);
}
//------------------------------------------------------------------------------
void pfcp_l4_stack::stop_msg_retry_timer(pfcp_procedure& p)
{
  if (p.retry_timer_id) {
    itti_inst->timer_remove(p.retry_timer_id);
    msg_out_retry_timers.erase(p.retry_timer_id);
    Logger::pfcp().trace( "Stopped Msg retry timer %d, proc %" PRId64", seq %d",p.retry_timer_id, p.pfcp_tx_id, p.retry_msg.get()->get_sequence_number());
    p.retry_timer_id = 0;
  }
}
//------------------------------------------------------------------------------
void pfcp_l4_stack::stop_msg_retry_timer(oai::cn::core::itti::timer_id_t& t)
{
  itti_inst->timer_remove(t);
  msg_out_retry_timers.erase(t);
  Logger::pfcp().trace( "Stopped Msg retry timer %d",t);
}
//------------------------------------------------------------------------------
void pfcp_l4_stack::start_proc_cleanup_timer(pfcp_procedure& p, uint32_t time_out_milli_seconds, const task_id_t& task_id, const uint32_t& seq_num)
{
  p.proc_cleanup_timer_id = itti_inst->timer_setup (time_out_milli_seconds/1000, time_out_milli_seconds%1000, task_id);
  proc_cleanup_timers.insert(std::pair<core::itti::timer_id_t, uint32_t>(p.proc_cleanup_timer_id, seq_num));
  Logger::pfcp().trace( "Started proc cleanup timer %d, proc %" PRId64" t-out %" PRIu32" ms",p.proc_cleanup_timer_id,p.pfcp_tx_id, time_out_milli_seconds);
}
//------------------------------------------------------------------------------
void pfcp_l4_stack::stop_proc_cleanup_timer(pfcp_procedure& p)
{
  itti_inst->timer_remove(p.proc_cleanup_timer_id);
  Logger::pfcp().trace( "Stopped proc cleanup timer %d, proc %" PRId64"",p.proc_cleanup_timer_id, p.pfcp_tx_id);
  msg_out_retry_timers.erase(p.proc_cleanup_timer_id);
  p.proc_cleanup_timer_id = 0;
}
//------------------------------------------------------------------------------
void pfcp_l4_stack::handle_receive_message_cb(const pfcp_msg& msg, const boost::asio::ip::udp::endpoint& remote_endpoint, const task_id_t& task_id, bool &error, uint64_t& pfcp_tx_id)
{
  pfcp_tx_id = 0;
  error = true;
  std::map<uint32_t , pfcp_procedure>::iterator it;
  it = pending_procedures.find(msg.get_sequence_number());
  if (it == pending_procedures.end()) {
    if (pfcp_l4_stack::check_request_type(msg.get_message_type())) {
      pfcp_procedure proc = {};
      proc.pfcp_tx_id = generate_pfcp_tx_id();
      proc.initial_msg_type = msg.get_message_type();
      // TODO later 13.3 Detection and handling of requests which have timed out at the originating entity
      // if (msg_has_timestamp()) {
      // start_proc_cleanup_timer(proc, (N3+1) x T3, task_id, msg.get_sequence_number());
      // } else
      start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
      pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
      pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));
      error = false;
      pfcp_tx_id = proc.pfcp_tx_id;
      Logger::pfcp().info( "Received Initial PFCP msg type %d, seq %d, proc %" PRId64"", msg.get_message_type(), msg.get_sequence_number(), proc.pfcp_tx_id);
    } else {
      Logger::pfcp().info( "Failed to check Initial message type, Silently discarding PFCP msg type %d, seq %d", msg.get_message_type(), msg.get_sequence_number());
      error = true;
    }
    return;
  } else {
//    Logger::pfcp().info( "pfcp_procedure retry_timer_id        %d", it->second.retry_timer_id);
//    Logger::pfcp().info( "pfcp_procedure proc_cleanup_timer_id %d", it->second.proc_cleanup_timer_id);
//    Logger::pfcp().info( "pfcp_procedure pfcp_tx_id            %ld", it->second.pfcp_tx_id);
//    Logger::pfcp().info( "pfcp_procedure initial_msg_type      %d", it->second.initial_msg_type);
//    Logger::pfcp().info( "pfcp_procedure triggered_msg_type    %d", it->second.triggered_msg_type);
//    Logger::pfcp().info( "pfcp_procedure retry_count           %d", it->second.retry_count);

    uint8_t check_initial_msg_type = it->second.triggered_msg_type;
    if (!it->second.triggered_msg_type) {
      check_initial_msg_type = it->second.initial_msg_type;
    }
    if (pfcp_l4_stack::check_response_type(check_initial_msg_type, msg.get_message_type())) {
      if (!it->second.triggered_msg_type) {
        it->second.triggered_msg_type = msg.get_message_type();
      }
      error = false;
      pfcp_tx_id = it->second.pfcp_tx_id;
      if (it->second.retry_timer_id) {
        stop_msg_retry_timer(it->second);
      }
      Logger::pfcp().info( "Received Triggered PFCP msg type %d, seq %d, proc %" PRId64"", msg.get_message_type(), msg.get_sequence_number(), pfcp_tx_id);
    } else {
      Logger::pfcp().info( "Failed to check Triggered message type, Silently discarding PFCP msg type %d, seq %d", msg.get_message_type(), msg.get_sequence_number());
      error = true;
    }
  }
}

////------------------------------------------------------------------------------
//uint32_t pfcp_l4_stack::send_request(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_pfd_management_request& pfcp_ies, const task_id_t& task_id, const uint64_t pfcp_tx_id)
//{
//  std::ostringstream oss(std::ostringstream::binary);
//  pfcp_msg msg(pfcp_ies);
//  msg.set_seid(seid);
//  msg.set_sequence_number(get_next_seq_num());
//  msg.dump_to(oss);
//  //std::cout << string_to_hex(oss.str()) << std::endl;
//  //std::cout << std::hex << "msg length 0x" << msg.get_message_length() << "msg seqnum 0x" << msg.get_sequence_number() << std::endl;
//  boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
//
//  Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
//  pfcp_procedure proc = {};
//  proc.initial_msg_type = msg.get_message_type();
//  proc.pfcp_tx_id = pfcp_tx_id;
//  proc.retry_msg = std::make_shared<pfcp_msg>(msg);
//  proc.remote_endpoint = dest;
//  start_msg_retry_timer(proc, PFCP_T1_RESPONSE_MS, task_id, msg.get_sequence_number());
//  start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
//  pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
//  pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));
//
//  udp_s.async_send_to(sm, dest);
//  return msg.get_sequence_number();
//}
////------------------------------------------------------------------------------
//uint32_t pfcp_l4_stack::send_request(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_association_setup_request& pfcp_ies, const task_id_t& task_id, const uint64_t pfcp_tx_id)
//{
//  std::ostringstream oss(std::ostringstream::binary);
//  pfcp_msg msg(pfcp_ies);
//  msg.set_seid(seid);
//  msg.set_sequence_number(get_next_seq_num());
//  msg.dump_to(oss);
//  //std::cout << string_to_hex(oss.str()) << std::endl;
//  //std::cout << std::hex << "msg length 0x" << msg.get_message_length() << "msg seqnum 0x" << msg.get_sequence_number() << std::endl;
//  boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
//
//  Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
//  pfcp_procedure proc = {};
//  proc.initial_msg_type = msg.get_message_type();
//  proc.pfcp_tx_id = pfcp_tx_id;
//  proc.retry_msg = std::make_shared<pfcp_msg>(msg);
//  proc.remote_endpoint = dest;
//  start_msg_retry_timer(proc, PFCP_T1_RESPONSE_MS, task_id, msg.get_sequence_number());
//  start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
//  pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
//  pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));
//
//  udp_s.async_send_to(sm, dest);
//  return msg.get_sequence_number();
//}
////------------------------------------------------------------------------------
//uint32_t pfcp_l4_stack::send_request(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_association_update_request& pfcp_ies, const task_id_t& task_id, const uint64_t pfcp_tx_id)
//{
//  std::ostringstream oss(std::ostringstream::binary);
//  pfcp_msg msg(pfcp_ies);
//  msg.set_seid(seid);
//  msg.set_sequence_number(get_next_seq_num());
//  msg.dump_to(oss);
//  //std::cout << string_to_hex(oss.str()) << std::endl;
//  //std::cout << std::hex << "msg length 0x" << msg.get_message_length() << "msg seqnum 0x" << msg.get_sequence_number() << std::endl;
//  boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
//
//  Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
//  pfcp_procedure proc = {};
//  proc.initial_msg_type = msg.get_message_type();
//  proc.pfcp_tx_id = pfcp_tx_id;
//  proc.retry_msg = std::make_shared<pfcp_msg>(msg);
//  proc.remote_endpoint = dest;
//  start_msg_retry_timer(proc, PFCP_T1_RESPONSE_MS, task_id, msg.get_sequence_number());
//  start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
//  pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
//  pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));
//
//  udp_s.async_send_to(sm, dest);
//  return msg.get_sequence_number();
//}
////------------------------------------------------------------------------------
//uint32_t pfcp_l4_stack::send_request(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_association_release_request& pfcp_ies, const task_id_t& task_id, const uint64_t pfcp_tx_id)
//{
//  std::ostringstream oss(std::ostringstream::binary);
//  pfcp_msg msg(pfcp_ies);
//  msg.set_seid(seid);
//  msg.set_sequence_number(get_next_seq_num());
//  msg.dump_to(oss);
//  //std::cout << string_to_hex(oss.str()) << std::endl;
//  //std::cout << std::hex << "msg length 0x" << msg.get_message_length() << "msg seqnum 0x" << msg.get_sequence_number() << std::endl;
//  boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
//
//  Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
//  pfcp_procedure proc = {};
//  proc.initial_msg_type = msg.get_message_type();
//  proc.pfcp_tx_id = pfcp_tx_id;
//  proc.retry_msg = std::make_shared<pfcp_msg>(msg);
//  proc.remote_endpoint = dest;
//  start_msg_retry_timer(proc, PFCP_T1_RESPONSE_MS, task_id, msg.get_sequence_number());
//  start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
//  pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
//  pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));
//
//  udp_s.async_send_to(sm, dest);
//  return msg.get_sequence_number();
//}
////------------------------------------------------------------------------------
//uint32_t pfcp_l4_stack::send_request(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_node_report_request& pfcp_ies, const task_id_t& task_id, const uint64_t pfcp_tx_id)
//{
//  std::ostringstream oss(std::ostringstream::binary);
//  pfcp_msg msg(pfcp_ies);
//  msg.set_seid(seid);
//  msg.set_sequence_number(get_next_seq_num());
//  msg.dump_to(oss);
//  //std::cout << string_to_hex(oss.str()) << std::endl;
//  //std::cout << std::hex << "msg length 0x" << msg.get_message_length() << "msg seqnum 0x" << msg.get_sequence_number() << std::endl;
//  boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
//
//  Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
//  pfcp_procedure proc = {};
//  proc.initial_msg_type = msg.get_message_type();
//  proc.pfcp_tx_id = pfcp_tx_id;
//  proc.retry_msg = std::make_shared<pfcp_msg>(msg);
//  proc.remote_endpoint = dest;
//  start_msg_retry_timer(proc, PFCP_T1_RESPONSE_MS, task_id, msg.get_sequence_number());
//  start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
//  pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
//  pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));
//
//  udp_s.async_send_to(sm, dest);
//  return msg.get_sequence_number();
//}
//------------------------------------------------------------------------------
uint32_t pfcp_l4_stack::send_request(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_session_establishment_request& pfcp_ies, const task_id_t& task_id, const uint64_t pfcp_tx_id)
{
  std::ostringstream oss(std::ostringstream::binary);
  pfcp_msg msg(pfcp_ies);
  msg.set_seid(seid);
  msg.set_sequence_number(get_next_seq_num());
  msg.dump_to(oss);
  //std::cout << string_to_hex(oss.str()) << std::endl;
  //std::cout << std::hex << "msg length 0x" << msg.get_message_length() << "msg seqnum 0x" << msg.get_sequence_number() << std::endl;
  boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));

  Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
  pfcp_procedure proc = {};
  proc.initial_msg_type = msg.get_message_type();
  proc.pfcp_tx_id = pfcp_tx_id;
  proc.retry_msg = std::make_shared<pfcp_msg>(msg);
  proc.remote_endpoint = dest;
  start_msg_retry_timer(proc, PFCP_T1_RESPONSE_MS, task_id, msg.get_sequence_number());
  start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
  pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
  pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));

  udp_s.async_send_to(sm, dest);
  return msg.get_sequence_number();
}
////------------------------------------------------------------------------------
//uint32_t pfcp_l4_stack::send_request(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_session_modification_request& pfcp_ies, const task_id_t& task_id, const uint64_t pfcp_tx_id)
//{
//  std::ostringstream oss(std::ostringstream::binary);
//  pfcp_msg msg(pfcp_ies);
//  msg.set_seid(seid);
//  msg.set_sequence_number(get_next_seq_num());
//  msg.dump_to(oss);
//  //std::cout << string_to_hex(oss.str()) << std::endl;
//  //std::cout << std::hex << "msg length 0x" << msg.get_message_length() << "msg seqnum 0x" << msg.get_sequence_number() << std::endl;
//  boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
//
//  Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
//  pfcp_procedure proc = {};
//  proc.initial_msg_type = msg.get_message_type();
//  proc.pfcp_tx_id = pfcp_tx_id;
//  proc.retry_msg = std::make_shared<pfcp_msg>(msg);
//  proc.remote_endpoint = dest;
//  start_msg_retry_timer(proc, PFCP_T1_RESPONSE_MS, task_id, msg.get_sequence_number());
//  start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
//  pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
//  pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));
//
//  udp_s.async_send_to(sm, dest);
//  return msg.get_sequence_number();
//}
////------------------------------------------------------------------------------
//uint32_t pfcp_l4_stack::send_request(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_session_deletion_request& pfcp_ies, const task_id_t& task_id, const uint64_t pfcp_tx_id)
//{
//  std::ostringstream oss(std::ostringstream::binary);
//  pfcp_msg msg(pfcp_ies);
//  msg.set_seid(seid);
//  msg.set_sequence_number(get_next_seq_num());
//  msg.dump_to(oss);
//  //std::cout << string_to_hex(oss.str()) << std::endl;
//  //std::cout << std::hex << "msg length 0x" << msg.get_message_length() << "msg seqnum 0x" << msg.get_sequence_number() << std::endl;
//  boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
//
//  Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
//  pfcp_procedure proc = {};
//  proc.initial_msg_type = msg.get_message_type();
//  proc.pfcp_tx_id = pfcp_tx_id;
//  proc.retry_msg = std::make_shared<pfcp_msg>(msg);
//  proc.remote_endpoint = dest;
//  start_msg_retry_timer(proc, PFCP_T1_RESPONSE_MS, task_id, msg.get_sequence_number());
//  start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
//  pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
//  pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));
//
//  udp_s.async_send_to(sm, dest);
//  return msg.get_sequence_number();
//}
////------------------------------------------------------------------------------
//uint32_t pfcp_l4_stack::send_request(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_session_report_request& pfcp_ies, const task_id_t& task_id, const uint64_t pfcp_tx_id)
//{
//  std::ostringstream oss(std::ostringstream::binary);
//  pfcp_msg msg(pfcp_ies);
//  msg.set_seid(seid);
//  msg.set_sequence_number(get_next_seq_num());
//  msg.dump_to(oss);
//  //std::cout << string_to_hex(oss.str()) << std::endl;
//  //std::cout << std::hex << "msg length 0x" << msg.get_message_length() << "msg seqnum 0x" << msg.get_sequence_number() << std::endl;
//  boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
//
//  Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
//  pfcp_procedure proc = {};
//  proc.initial_msg_type = msg.get_message_type();
//  proc.pfcp_tx_id = pfcp_tx_id;
//  proc.retry_msg = std::make_shared<pfcp_msg>(msg);
//  proc.remote_endpoint = dest;
//  start_msg_retry_timer(proc, PFCP_T1_RESPONSE_MS, task_id, msg.get_sequence_number());
//  start_proc_cleanup_timer(proc, PFCP_PROC_TIME_OUT_MS, task_id, msg.get_sequence_number());
//  pending_procedures.insert(std::pair<uint32_t, pfcp_procedure>(msg.get_sequence_number(), proc));
//  pfcp_tx_id2seq_num.insert(std::pair<uint64_t, uint32_t>(proc.pfcp_tx_id, msg.get_sequence_number()));
//
//  udp_s.async_send_to(sm, dest);
//  return msg.get_sequence_number();
//}
//
////------------------------------------------------------------------------------
//void pfcp_l4_stack::send_response(const boost::asio::ip::udp::endpoint& dest, const uint64_t seid, const pfcp_pfd_management_response& pfcp_ies, const uint64_t pfcp_tx_id, const pfcp_transaction_action& a)
//{
//  std::map<uint64_t , uint32_t>::iterator it;
//  it = pfcp_tx_id2seq_num.find(pfcp_tx_id);
//  if (it != pfcp_tx_id2seq_num.end()) {
//    std::ostringstream oss(std::ostringstream::binary);
//    pfcp_msg msg(pfcp_ies);
//    msg.set_seid(seid);
//    msg.set_sequence_number(it->second);
//    msg.dump_to(oss);
//    boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
//    Logger::pfcp().trace( "Sending %s, seq %d", pfcp_ies.get_msg_name(), msg.get_sequence_number());
//    udp_s.async_send_to(sm, dest);
//
//    if (a == DELETE_TX) {
//      std::map<uint32_t , pfcp_procedure>::iterator it_proc = pending_procedures.find(it->second);
//      if (it_proc != pending_procedures.end()) {
//        stop_proc_cleanup_timer(it_proc->second);
//        pending_procedures.erase(it_proc);
//      }
//      pfcp_tx_id2seq_num.erase(it);
//    }
//  } else {
//    Logger::pfcp().error( "Sending %s, pfcp_tx_id %ld proc not found, discarded!", pfcp_ies.get_msg_name(), pfcp_tx_id);
//  }
//}

//------------------------------------------------------------------------------
void pfcp_l4_stack::notify_ul_error(const pfcp_procedure& p, const core::cause_value_e cause)
{
  Logger::pfcp().trace( "notify_ul_error proc %" PRId64" cause %d", p.pfcp_tx_id, cause);
}
//------------------------------------------------------------------------------
void pfcp_l4_stack::time_out_event(const uint32_t timer_id, const task_id_t& task_id, bool &handled)
{
  handled = false;
  std::map<core::itti::timer_id_t, uint32_t>::iterator it = msg_out_retry_timers.find(timer_id);
  if (it != msg_out_retry_timers.end()) {
    std::map<uint32_t , pfcp_procedure>::iterator it_proc = pending_procedures.find(it->second);
    msg_out_retry_timers.erase(it);
    handled = true;
    if (it_proc != pending_procedures.end()) {
      if (it_proc->second.retry_count < PFCP_N1_REQUESTS) {
        it_proc->second.retry_count++;
        start_msg_retry_timer(it_proc->second, PFCP_T1_RESPONSE_MS, task_id, it_proc->second.retry_msg.get()->get_sequence_number());
        // send again message
        Logger::pfcp().trace( "Retry %d Sending msg type %d, seq %d",
            it_proc->second.retry_count, it_proc->second.retry_msg.get()->get_message_type(), it_proc->second.retry_msg.get()->get_sequence_number());
        std::ostringstream oss(std::ostringstream::binary);
        it_proc->second.retry_msg.get()->dump_to(oss);
        boost::shared_ptr<std::string> sm = boost::shared_ptr<std::string>(new std::string(oss.str()));
        udp_s.async_send_to(sm, it_proc->second.remote_endpoint);
      } else {
        // abort procedure
        notify_ul_error(it_proc->second, core::cause_value_e::REMOTE_PEER_NOT_RESPONDING);
      }
    }
  } else {
    it = proc_cleanup_timers.find(timer_id);
    if (it != proc_cleanup_timers.end()) {
      std::map<uint32_t , pfcp_procedure>::iterator it_proc = pending_procedures.find(it->second);
      proc_cleanup_timers.erase(it);
      handled = true;
      if (it_proc != pending_procedures.end()) {
        it_proc->second.proc_cleanup_timer_id = 0;
        Logger::pfcp().trace( "Delete proc %" PRId64" Retry %d seq %d timer id %u",
            it_proc->second.pfcp_tx_id, it_proc->second.retry_count, it_proc->first, timer_id);
        pending_procedures.erase(it_proc);
      }
    }
  }
}

