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

/*! \file 3gpp_129.244.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/


#include "3gpp_129.244.hpp"

#include <string>

using namespace oai::cn::proto::pfcp;
using namespace oai::cn::core::pfcp;
using namespace oai::cn::core;

//------------------------------------------------------------------------------
pfcp_ie * pfcp_ie::new_pfcp_ie_from_stream(std::istream& is) {
  pfcp_tlv    tlv;
  tlv.load_from(is);
  if (tlv.length) {
    switch (tlv.type) {
    case PFCP_IE_CREATE_PDR: {
        pfcp_create_pdr_ie *ie = new pfcp_create_pdr_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_PDI: {
        pfcp_pdi_ie *ie = new pfcp_pdi_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_CREATE_FAR: {
        pfcp_create_far_ie *ie = new pfcp_create_far_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_FORWARDING_PARAMETERS: {
        pfcp_forwarding_parameters_ie *ie = new pfcp_forwarding_parameters_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_DUPLICATING_PARAMETERS: {
        pfcp_duplicating_parameters_ie *ie = new pfcp_duplicating_parameters_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_CREATE_URR: {
        pfcp_create_urr_ie *ie = new pfcp_create_urr_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_CREATE_QER: {
        pfcp_create_qer_ie *ie = new pfcp_create_qer_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_CREATED_PDR: {
        pfcp_created_pdr_ie *ie = new pfcp_created_pdr_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_UPDATE_PDR: {
        pfcp_update_pdr_ie *ie = new pfcp_update_pdr_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_UPDATE_FAR: {
        pfcp_update_far_ie *ie = new pfcp_update_far_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_UPDATE_FORWARDING_PARAMETERS: {
        pfcp_update_forwarding_parameters_ie *ie = new pfcp_update_forwarding_parameters_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_UPDATE_BAR_WITHIN_PFCP_SESSION_REPORT_RESPONSE: {
        pfcp_update_bar_within_pfcp_session_report_response_ie *ie = new pfcp_update_bar_within_pfcp_session_report_response_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_UPDATE_URR: {
        pfcp_update_urr_ie *ie = new pfcp_update_urr_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_UPDATE_QER: {
        pfcp_update_qer_ie *ie = new pfcp_update_qer_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_REMOVE_PDR: {
        pfcp_remove_pdr_ie *ie = new pfcp_remove_pdr_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_REMOVE_FAR: {
        pfcp_remove_far_ie *ie = new pfcp_remove_far_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_REMOVE_URR: {
        pfcp_remove_urr_ie *ie = new pfcp_remove_urr_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_REMOVE_QER: {
        pfcp_remove_qer_ie *ie = new pfcp_remove_qer_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_CAUSE: {
        pfcp_cause_ie *ie = new pfcp_cause_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_SOURCE_INTERFACE: {
        pfcp_source_interface_ie *ie = new pfcp_source_interface_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_F_TEID: {
        pfcp_f_teid_ie *ie = new pfcp_f_teid_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_NETWORK_INSTANCE: {
        pfcp_network_instance_ie *ie = new pfcp_network_instance_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_SDF_FILTER: {
        pfcp_sdf_filter_ie *ie = new pfcp_sdf_filter_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_APPLICATION_ID: {
        pfcp_application_id_ie *ie = new pfcp_application_id_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_GATE_STATUS: {
        pfcp_gate_status_ie *ie = new pfcp_gate_status_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_MBR: {
        pfcp_mbr_ie *ie = new pfcp_mbr_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_GBR: {
        pfcp_gbr_ie *ie = new pfcp_gbr_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_QER_CORRELATION_ID: {
        pfcp_qer_correlation_id_ie *ie = new pfcp_qer_correlation_id_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_PRECEDENCE: {
        pfcp_precedence_ie *ie = new pfcp_precedence_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_TRANSPORT_LEVEL_MARKING: {
        pfcp_transport_level_marking_ie *ie = new pfcp_transport_level_marking_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_VOLUME_THRESHOLD: {
        pfcp_volume_threshold_ie *ie = new pfcp_volume_threshold_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_TIME_THRESHOLD: {
        pfcp_time_threshold_ie *ie = new pfcp_time_threshold_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_MONITORING_TIME: {
        pfcp_monitoring_time_ie *ie = new pfcp_monitoring_time_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD: {
        pfcp_subsequent_volume_threshold_ie *ie = new pfcp_subsequent_volume_threshold_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_SUBSEQUENT_TIME_THRESHOLD: {
        pfcp_subsequent_time_threshold_ie *ie = new pfcp_subsequent_time_threshold_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_INACTIVITY_DETECTION_TIME: {
        pfcp_inactivity_detection_time_ie *ie = new pfcp_inactivity_detection_time_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_REPORTING_TRIGGERS: {
        pfcp_reporting_triggers_ie *ie = new pfcp_reporting_triggers_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
//    case PFCP_IE_REDIRECT_INFORMATION: {
//        pfcp_redirect_information_ie *ie = new pfcp_redirect_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_REPORT_TYPE: {
//        pfcp_report_type_ie *ie = new pfcp_report_type_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_OFFENDING_IE: {
//        pfcp_offending_ie_ie *ie = new pfcp_offending_ie_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_FORWARDING_POLICY: {
//        pfcp_forwarding_policy_ie *ie = new pfcp_forwarding_policy_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_DESTINATION_INTERFACE: {
//        pfcp_destination_interface_ie *ie = new pfcp_destination_interface_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_UP_FUNCTION_FEATURES: {
//        pfcp_up_function_features_ie *ie = new pfcp_up_function_features_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_APPLY_ACTION: {
//        pfcp_apply_action_ie *ie = new pfcp_apply_action_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION: {
//        pfcp_downlink_data_service_information_ie *ie = new pfcp_downlink_data_service_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY: {
//        pfcp_downlink_data_notification_delay_ie *ie = new pfcp_downlink_data_notification_delay_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_DL_BUFFERING_DURATION: {
//        pfcp_dl_buffering_duration_ie *ie = new pfcp_dl_buffering_duration_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT: {
//        pfcp_dl_buffering_suggested_packet_count_ie *ie = new pfcp_dl_buffering_suggested_packet_count_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_PFCPSMREQ_FLAGS: {
//        pfcp_pfcpsmreq_flags_ie *ie = new pfcp_pfcpsmreq_flags_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_PFCPSRRSP_FLAGS: {
//        pfcp_pfcpsrrsp_flags_ie *ie = new pfcp_pfcpsrrsp_flags_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_LOAD_CONTROL_INFORMATION: {
//        pfcp_load_control_information_ie *ie = new pfcp_load_control_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_SEQUENCE_NUMBER: {
//        pfcp_sequence_number_ie *ie = new pfcp_sequence_number_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_METRIC: {
//        pfcp_metric_ie *ie = new pfcp_metric_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_OVERLOAD_CONTROL_INFORMATION: {
//        pfcp_overload_control_information_ie *ie = new pfcp_overload_control_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_TIMER: {
//        pfcp_timer_ie *ie = new pfcp_timer_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
    case PFCP_IE_PACKET_DETECTION_RULE_ID: {
        pfcp_pdr_id_ie *ie = new pfcp_pdr_id_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_F_SEID: {
        pfcp_f_seid_ie *ie = new pfcp_f_seid_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
//    case PFCP_IE_APPLICATION_IDS_PFDS: {
//        pfcp_application_ids_pfds_ie *ie = new pfcp_application_ids_pfds_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_PFD: {
//        pfcp_pfd_ie *ie = new pfcp_pfd_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
    case PFCP_IE_NODE_ID: {
        pfcp_node_id_ie *ie = new pfcp_node_id_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
//    case PFCP_IE_PFD_CONTENTS: {
//        pfcp_pfd_contents_ie *ie = new pfcp_pfd_contents_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_MEASUREMENT_METHOD: {
//        pfcp_measurement_method_ie *ie = new pfcp_measurement_method_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_USAGE_REPORT_TRIGGER: {
//        pfcp_usage_report_trigger_ie *ie = new pfcp_usage_report_trigger_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_MEASUREMENT_PERIOD: {
//        pfcp_measurement_period_ie *ie = new pfcp_measurement_period_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_FQ_CSID: {
//        pfcp_fq_csid_ie *ie = new pfcp_fq_csid_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_VOLUME_MEASUREMENT: {
//        pfcp_volume_measurement_ie *ie = new pfcp_volume_measurement_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_DURATION_MEASUREMENT: {
//        pfcp_duration_measurement_ie *ie = new pfcp_duration_measurement_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_APPLICATION_DETECTION_INFORMATION: {
//        pfcp_application_detection_information_ie *ie = new pfcp_application_detection_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_TIME_OF_FIRST_PACKET: {
//        pfcp_time_of_first_packet_ie *ie = new pfcp_time_of_first_packet_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_TIME_OF_LAST_PACKET: {
//        pfcp_time_of_last_packet_ie *ie = new pfcp_time_of_last_packet_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_QUOTA_HOLDING_TIME: {
//        pfcp_quota_holding_time_ie *ie = new pfcp_quota_holding_time_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD: {
//        pfcp_dropped_dl_traffic_threshold_ie *ie = new pfcp_dropped_dl_traffic_threshold_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_VOLUME_QUOTA: {
//        pfcp_volume_quota_ie *ie = new pfcp_volume_quota_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_TIME_QUOTA: {
//        pfcp_time_quota_ie *ie = new pfcp_time_quota_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_START_TIME: {
//        pfcp_start_time_ie *ie = new pfcp_start_time_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_END_TIME: {
//        pfcp_end_time_ie *ie = new pfcp_end_time_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_QUERY_URR: {
//        pfcp_query_urr_ie *ie = new pfcp_query_urr_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_USAGE_REPORT_WITHIN_SESSION_MODIFICATION_RESPONSE: {
//        pfcp_usage_report_within_session_modification_response_ie *ie = new pfcp_usage_report_within_session_modification_response_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_USAGE_REPORT_WITHIN_SESSION_DELETION_RESPONSE: {
//        pfcp_usage_report_within_session_deletion_response_ie *ie = new pfcp_usage_report_within_session_deletion_response_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_USAGE_REPORT_WITHIN_SESSION_REPORT_REQUEST: {
//        pfcp_usage_report_within_session_report_request_ie *ie = new pfcp_usage_report_within_session_report_request_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
    case PFCP_IE_URR_ID: {
        pfcp_urr_id_ie *ie = new pfcp_urr_id_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
//    case PFCP_IE_LINKED_URR_ID: {
//        pfcp_linked_urr_id_ie *ie = new pfcp_linked_urr_id_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_DOWNLINK_DATA_REPORT: {
//        pfcp_downlink_data_report_ie *ie = new pfcp_downlink_data_report_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_OUTER_HEADER_CREATION: {
//        pfcp_outer_header_creation_ie *ie = new pfcp_outer_header_creation_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_CREATE_BAR: {
//        pfcp_create_bar_ie *ie = new pfcp_create_bar_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_UPDATE_BAR_WITHIN_PFCP_SESSION_MODIFICATION_REQUEST: {
//        pfcp_update_bar_within_session_modification_request_ie *ie = new pfcp_update_bar_within_session_modification_request_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_REMOVE_BAR: {
//        pfcp_remove_bar_ie *ie = new pfcp_remove_bar_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_BAR_ID: {
//        pfcp_bar_id_ie *ie = new pfcp_bar_id_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_CP_FUNCTION_FEATURES: {
//        pfcp_cp_function_features_ie *ie = new pfcp_cp_function_features_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_USAGE_INFORMATION: {
//        pfcp_usage_information_ie *ie = new pfcp_usage_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_APPLICATION_INSTANCE_ID: {
//        pfcp_application_instance_id_ie *ie = new pfcp_application_instance_id_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_FLOW_INFORMATION: {
//        pfcp_flow_information_ie *ie = new pfcp_flow_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
    case PFCP_IE_UE_IP_ADDRESS: {
        pfcp_ue_ip_address_ie *ie = new pfcp_ue_ip_address_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
//    case PFCP_IE_PACKET_RATE: {
//        pfcp_packet_rate_ie *ie = new pfcp_packet_rate_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
    case PFCP_IE_OUTER_HEADER_REMOVAL: {
        pfcp_outer_header_removal_ie *ie = new pfcp_outer_header_removal_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
//    case PFCP_IE_RECOVERY_TIME_STAMP: {
//        pfcp_recovery_time_stamp_ie *ie = new pfcp_recovery_time_stamp_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_DL_FLOW_LEVEL_MARKING: {
//        pfcp_dl_flow_level_marking_ie *ie = new pfcp_dl_flow_level_marking_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_HEADER_ENRICHMENT: {
//        pfcp_header_enrichment_ie *ie = new pfcp_header_enrichment_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_ERROR_INDICATION_REPORT: {
//        pfcp_error_indication_report_ie *ie = new pfcp_error_indication_report_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_MEASUREMENT_INFORMATION: {
//        pfcp_measurement_information_ie *ie = new pfcp_measurement_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_NODE_REPORT_TYPE: {
//        pfcp_node_report_type_ie *ie = new pfcp_node_report_type_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT: {
//        pfcp_user_plane_path_failure_report_ie *ie = new pfcp_user_plane_path_failure_report_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_REMOTE_GTP_U_PEER: {
//        pfcp_remote_gtp_u_peer_ie *ie = new pfcp_remote_gtp_u_peer_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_UR_SEQN: {
//        pfcp_ur_seqn_ie *ie = new pfcp_ur_seqn_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_UPDATE_DUPLICATING_PARAMETERS: {
//        pfcp_update_duplicating_parameters_ie *ie = new pfcp_update_duplicating_parameters_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
    case PFCP_IE_ACTIVATE_PREDEFINED_RULES: {
        pfcp_activate_predefined_rules_ie *ie = new pfcp_activate_predefined_rules_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_DEACTIVATE_PREDEFINED_RULES: {
        pfcp_deactivate_predefined_rules_ie *ie = new pfcp_deactivate_predefined_rules_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_FAR_ID: {
        pfcp_far_id_ie *ie = new pfcp_far_id_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
    case PFCP_IE_QER_ID: {
        pfcp_qer_id_ie *ie = new pfcp_qer_id_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
//    case PFCP_IE_OCI_FLAGS: {
//        pfcp_oci_flags_ie *ie = new pfcp_oci_flags_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST: {
//        pfcp_pfcp_association_release_request_ie *ie = new pfcp_pfcp_association_release_request_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_GRACEFUL_RELEASE_PERIOD: {
//        pfcp_graceful_release_period_ie *ie = new pfcp_graceful_release_period_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_PDN_TYPE: {
//        pfcp_pdn_type_ie *ie = new pfcp_pdn_type_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_FAILED_RULE_ID: {
//        pfcp_failed_rule_id_ie *ie = new pfcp_failed_rule_id_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_TIME_QUOTA_MECHANISM: {
//        pfcp_time_quota_mechanism_ie *ie = new pfcp_time_quota_mechanism_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION: {
//        pfcp_user_plane_ip_resource_information_ie *ie = new pfcp_user_plane_ip_resource_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
    case PFCP_IE_USER_PLANE_INACTIVITY_TIMER: {
        pfcp_user_plane_inactivity_timer_ie *ie = new pfcp_user_plane_inactivity_timer_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
//    case PFCP_IE_AGGREGATED_URRS: {
//        pfcp_aggregated_urrs_ie *ie = new pfcp_aggregated_urrs_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_MULTIPLIER: {
//        pfcp_multiplier_ie *ie = new pfcp_multiplier_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_AGGREGATED_URR_ID: {
//        pfcp_aggregated_urr_id_ie *ie = new pfcp_aggregated_urr_id_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_SUBSEQUENT_VOLUME_QUOTA: {
//        pfcp_subsequent_volume_quota_ie *ie = new pfcp_subsequent_volume_quota_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_SUBSEQUENT_TIME_QUOTA: {
//        pfcp_subsequent_time_quota_ie *ie = new pfcp_subsequent_time_quota_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_RQI: {
//        pfcp_rqi_ie *ie = new pfcp_rqi_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_QFI: {
//        pfcp_qfi_ie *ie = new pfcp_qfi_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_QUERY_URR_REFERENCE: {
//        pfcp_query_urr_reference_ie *ie = new pfcp_query_urr_reference_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION: {
//        pfcp_additional_usage_reports_information_ie *ie = new pfcp_additional_usage_reports_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_CREATE_TRAFFIC_ENDPOINT: {
//        pfcp_create_traffic_endpoint_ie *ie = new pfcp_create_traffic_endpoint_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_CREATED_TRAFFIC_ENDPOINT: {
//        pfcp_created_traffic_endpoint_ie *ie = new pfcp_created_traffic_endpoint_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_UPDATE_TRAFFIC_ENDPOINT: {
//        pfcp_update_traffic_endpoint_ie *ie = new pfcp_update_traffic_endpoint_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_REMOVE_TRAFFIC_ENDPOINT: {
//        pfcp_remove_traffic_endpoint_ie *ie = new pfcp_remove_traffic_endpoint_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_TRAFFIC_ENDPOINT_ID: {
//        pfcp_traffic_endpoint_id_ie *ie = new pfcp_traffic_endpoint_id_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_ETHERNET_PACKET_FILTER: {
//        pfcp_ethernet_packet_filter_ie *ie = new pfcp_ethernet_packet_filter_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_MAC_ADDRESS: {
//        pfcp_mac_address_ie *ie = new pfcp_mac_address_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_C_TAG: {
//        pfcp_c_tag_ie *ie = new pfcp_c_tag_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_S_TAG: {
//        pfcp_s_tag_ie *ie = new pfcp_s_tag_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_ETHERTYPE: {
//        pfcp_ethertype_ie *ie = new pfcp_ethertype_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_PROXYING: {
//        pfcp_proxying_ie *ie = new pfcp_proxying_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_ETHERNET_FILTER_ID: {
//        pfcp_ethernet_filter_id_ie *ie = new pfcp_ethernet_filter_id_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_ETHERNET_FILTER_PROPERTIES: {
//        pfcp_ethernet_filter_properties_ie *ie = new pfcp_ethernet_filter_properties_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT: {
//        pfcp_suggested_buffering_packets_count_ie *ie = new pfcp_suggested_buffering_packets_count_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
    case PFCP_IE_USER_ID: {
        pfcp_user_id_ie *ie = new pfcp_user_id_ie(tlv);
        ie->load_from(is);
        return ie;
      }
      break;
//    case PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION: {
//        pfcp_ethernet_pdu_session_information_ie *ie = new pfcp_ethernet_pdu_session_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_ETHERNET_TRAFFIC_INFORMATION: {
//        pfcp_ethernet_traffic_information_ie *ie = new pfcp_ethernet_traffic_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_MAC_ADDRESSES_DETECTED: {
//        pfcp_mac_addresses_detected_ie *ie = new pfcp_mac_addresses_detected_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_MAC_ADDRESSES_REMOVED: {
//        pfcp_mac_addresses_removed_ie *ie = new pfcp_mac_addresses_removed_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_ETHERNET_INACTIVITY_TIMER: {
//        pfcp_ethernet_inactivity_timer_ie *ie = new pfcp_ethernet_inactivity_timer_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_ADDITIONAL_MONITORING_TIME: {
//        pfcp_additional_monitoring_time_ie *ie = new pfcp_additional_monitoring_time_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_EVENT_INFORMATION: {
//        pfcp_event_information_ie *ie = new pfcp_event_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_EVENT_REPORTING: {
//        pfcp_event_reporting_ie *ie = new pfcp_event_reporting_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_EVENT_ID: {
//        pfcp_event_id_ie *ie = new pfcp_event_id_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_EVENT_THRESHOLD: {
//        pfcp_event_threshold_ie *ie = new pfcp_event_threshold_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_TRACE_INFORMATION: {
//        pfcp_trace_information_ie *ie = new pfcp_trace_information_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_FRAMED_ROUTE: {
//        pfcp_framed_route_ie *ie = new pfcp_framed_route_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_FRAMED_ROUTING: {
//        pfcp_framed_routing_ie *ie = new pfcp_framed_routing_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
//    case PFCP_IE_FRAMED_IPV6_ROUTE: {
//        pfcp_framed_ipv6_route_ie *ie = new pfcp_framed_ipv6_route_ie(tlv);
//        ie->load_from(is);
//        return ie;
//      }
//      break;
    default:
      Logger::pfcp().error("Unknown GTP IE type %d (length %d)", tlv.get_type(), tlv.get_length());
      return nullptr;
    }
  } else {
    Logger::pfcp().error("GTP IE type %d length %d", tlv.get_type(), tlv.get_length());
    return nullptr;
  }
}
//------------------------------------------------------------------------------
pfcp_msg::pfcp_msg(const pfcp_session_establishment_request& pfcp_ies) : pfcp_msg_header() {
  ies = {};
  set_message_type(PFCP_SESSION_ESTABLISHMENT_REQUEST);

  if (pfcp_ies.node_id.first) {std::shared_ptr<pfcp_node_id_ie> sie(new pfcp_node_id_ie(pfcp_ies.node_id.second)); add_ie(sie);}
  if (pfcp_ies.cp_fseid.first) {std::shared_ptr<pfcp_f_seid_ie> sie(new pfcp_f_seid_ie(pfcp_ies.cp_fseid.second)); add_ie(sie);}
  if (pfcp_ies.create_pdr.first) {std::shared_ptr<pfcp_create_pdr_ie> sie(new pfcp_create_pdr_ie(pfcp_ies.create_pdr.second)); add_ie(sie);}
  if (pfcp_ies.create_far.first) {std::shared_ptr<pfcp_create_far_ie> sie(new pfcp_create_far_ie(pfcp_ies.create_far.second)); add_ie(sie);}
  if (pfcp_ies.create_urr.first) {std::shared_ptr<pfcp_create_urr_ie> sie(new pfcp_create_urr_ie(pfcp_ies.create_urr.second)); add_ie(sie);}
  if (pfcp_ies.create_qer.first) {std::shared_ptr<pfcp_create_qer_ie> sie(new pfcp_create_qer_ie(pfcp_ies.create_qer.second)); add_ie(sie);}
//  if (pfcp_ies.create_bar.first) {std::shared_ptr<pfcp_create_bar_ie> sie(new pfcp_create_bar_ie(pfcp_ies.create_bar.second)); add_ie(sie);}
  if (pfcp_ies.create_traffic_endpoint.first) {std::shared_ptr<pfcp_create_traffic_endpoint_ie> sie(new pfcp_create_traffic_endpoint_ie(pfcp_ies.create_traffic_endpoint.second)); add_ie(sie);}
//  if (pfcp_ies.pdn_type.first) {std::shared_ptr<pfcp_pdn_type_ie> sie(new pfcp_pdn_type_ie(pfcp_ies.pdn_type.second)); add_ie(sie);}
//  if (pfcp_ies.sgw_c_fq_csid.first) {std::shared_ptr<pfcp_fq_csid_ie> sie(new pfcp_fq_csid_ie(pfcp_ies.sgw_c_fq_csid.second)); add_ie(sie);}
//  if (pfcp_ies.mme_fq_csid.first) {std::shared_ptr<pfcp_fq_csid_ie> sie(new pfcp_fq_csid_ie(pfcp_ies.mme_fq_csid.second)); add_ie(sie);}
//  if (pfcp_ies.pgw_c_fq_csid.first) {std::shared_ptr<pfcp_fq_csid_ie> sie(new pfcp_fq_csid_ie(pfcp_ies.pgw_c_fq_csid.second)); add_ie(sie);}
//  if (pfcp_ies.epdg_fq_csid.first) {std::shared_ptr<pfcp_fq_csid_ie> sie(new pfcp_fq_csid_ie(pfcp_ies.epdg_fq_csid.second)); add_ie(sie);}
//  if (pfcp_ies.twan_fq_csid.first) {std::shared_ptr<pfcp_fq_csid_ie> sie(new pfcp_fq_csid_ie(pfcp_ies.twan_fq_csid.second)); add_ie(sie);}
  if (pfcp_ies.user_plane_inactivity_timer.first) {std::shared_ptr<pfcp_user_plane_inactivity_timer_ie> sie(new pfcp_user_plane_inactivity_timer_ie(pfcp_ies.user_plane_inactivity_timer.second)); add_ie(sie);}
  if (pfcp_ies.user_id.first) {std::shared_ptr<pfcp_user_id_ie> sie(new pfcp_user_id_ie(pfcp_ies.user_id.second)); add_ie(sie);}
//  if (pfcp_ies.trace_information.first) {std::shared_ptr<pfcp_trace_information_ie> sie(new pfcp_trace_information_ie(pfcp_ies.trace_information.second)); add_ie(sie);}
}

