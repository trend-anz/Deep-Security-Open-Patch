import csv
import time
import os
import sys
from pprint import pformat
import json

import deepsecurity as api
from deepsecurity.rest import ApiException
from .loggers import Loggers

if os.path.exists('db.py'):
    from .db import SetupDb

PAGE_SIZE = 5000


class Ds:
    def __init__(self, app_name, console_logger=False, print_logger=False, log_level='INFO', log_file_path=''):
        """Initiate Ds class

        Completes the following tasks:
            * Looks for `DS_KEY` env var
            * Sets up logger
            * Sets up DB (if required)
            * Prepares DS API
        """
        self.app_name = app_name
        self.logger = Loggers(self.app_name, console_logger, print_logger, log_level, log_file_path)

        try:
            self.logger.entry('info', 'Obtaining DS API key')
            ds_api_key = os.environ['DS_KEY']
            self.api_version = os.environ.get('DS_API_VERSION', 'v1')
            self.logger.entry('info', f'Set API version to {self.api_version}')

        except KeyError:
            sys.exit('"DS_KEY" environment variables are not set. Please set them and try again.')

        dsm_address = self._get_env_var('DS_API_ADDRESS', 'https://app.deepsecurity.trendmicro.com/api')
        self.logger.entry('info', f'Obtained DS API address: {dsm_address}')

        self.enable_db_output = os.environ.get('DS_ENABLE_DB')
        if self.enable_db_output:
            self._db_setup()

        self.logger.entry('info', 'Initiating DS connection')
        config = api.Configuration()
        config.host = dsm_address
        config.api_key['api-secret-key'] = ds_api_key

        self.api_client = api.ApiClient(config)

    def get_app_types(self) -> dict:
        """App type map with App ID as key

        Examples:
            Output::

            {
                373: {
                    'description': '',
                    'direction': 'incoming',
                    'id': 373,
                    'minimum_agent_version': '4.0.0.0',
                    'name': 'Redis Server',
                    'port_list_id': None,
                    'port_multiple': ['6379'],
                    'port_type': 'multiple',
                    'protocol': 'tcp',
                    'recommendations_mode': None
                },
                397: {
                    'description': '',
                    'direction': 'incoming',
                    'id': 397,
                    'minimum_agent_version': '4.0.0.0',
                    'name': 'Mail Server Over SSL/TLS',
                    'port_list_id': None,
                    'port_multiple': ['25', '465', '587'],
                    'port_type': 'multiple',
                    'protocol': 'tcp',
                    'recommendations_mode': None
                },
                430: {
                    'description': '',
                    'direction': 'incoming',
                    'id': 430,
                    'minimum_agent_version': '4.0.0.0',
                    'name': 'SolarWinds Dameware Mini Remote Control',
                    'port_list_id': None,
                    'port_multiple': ['6129'],
                    'port_type': 'multiple',
                    'protocol': 'tcp',
                    'recommendations_mode': None
                },
                463: {
                    'description': '',
                    'direction': 'incoming',
                    'id': 463,
                    'minimum_agent_version': '4.0.0.0',
                    'name': 'Windows Remote Management',
                    'port_list_id': None,
                    'port_multiple': ['5985'],
                    'port_type': 'multiple',
                    'protocol': 'tcp',
                    'recommendations_mode': None
                }
            }


        Returns:
            dict: Dictionary of App Types
        """

        self.logger.entry('info', 'Obtaining app types...')

        try:
            app_type_api = api.ApplicationTypesApi(self.api_client)
            app_list = app_type_api.list_application_types(self.api_version)

        except ApiException as e:
            self.logger.entry('critical', str(e))
            sys.exit(1)

        app_types = dict()

        for app in app_list.application_types:
            app_types[app.id] = app

        num_app_types = len(app_types)
        self.logger.entry('info', f'Obtained {num_app_types} app types')
        self.logger.entry('debug', pformat(app_types))
        return app_types

    def get_computers(self) -> dict:
        """Computer details map with hostname as key

        Examples:
            Output::

            {
                'WIN-Q0HITV3HJ6D': {
                    'agent_finger_print': '4F:E3:DD:C1:FD:D1:FB:93:D8:D0:C3:21:69:5A:1C:83:F6:C1:1E:C2',
                    'agent_version': '12.0.0.563',
                    'anti_malware': None,
                    'appliance_finger_print': None,
                    'application_control': None,
                    'asset_importance_id': None,
                    'azure_arm_virtual_machine_summary': None,
                    'azure_vm_virtual_machine_summary': None,
                    'bios_uuid': 'ec2e87d1-b402-6bff-07f9-1cac94545a1c',
                    'computer_settings': None,
                    'computer_status': None,
                    'description': '',
                    'display_name': '',
                    'ec2_virtual_machine_summary': None,
                    'esx_summary': None,
                    'firewall': None,
                    'group_id': 0,
                    'host_name': 'WIN-Q0HITV3HJ6D',
                    'id': 34,
                    'integrity_monitoring': None,
                    'interfaces': None,
                    'intrusion_prevention': {
                        'application_type_ids': [117,
                            243,
                            268,
                            287,
                            299,
                            300,
                            301,
                            303,
                            304,
                            340,
                            352
                        ],
                        'module_status': {
                            'agent_status': 'inactive',
                            'agent_status_message': 'Off, '
                            'installed, '
                            '32 '
                            'rules',
                            'appliance_status': None,
                            'appliance_status_message': None
                        },
                        'rule_ids': [2013,
                            2285,
                            2302,
                            3218,
                            3441,
                            3600,
                            3812,
                            4167,
                            4282,
                            4432,
                            4456,
                            4458,
                            4459,
                            4460,
                            4461,
                            5400,
                            5403,
                            5762,
                            5763,
                            6281,
                            6282,
                            6298,
                            6308,
                            6378,
                            6379,
                            6419,
                            6425,
                            6676,
                            6699,
                            6700,
                            6774,
                            7007
                        ],
                        'state': 'off'
                    },
                    'last_agent_communication': 1569411611641,
                    'last_appliance_communication': None,
                    'last_ip_used': '192.168.22.2',
                    'last_send_policy_request': 1573101479760,
                    'last_send_policy_success': 1569386473666,
                    'log_inspection': None,
                    'no_connector_virtual_machine_summary': None,
                    'platform': 'Microsoft Windows Server 2008 R2 (64 bit) '
                    'Service Pack 1 Build 7601',
                    'policy_id': 54,
                    'relay_list_id': 0,
                    'sap': None,
                    'security_updates': None,
                    'tasks': None,
                    'vcloud_vm_virtual_machine_summary': None,
                    'vmware_vm_virtual_machine_summary': None,
                    'web_reputation': None,
                    'workspace_virtual_machine_summary': None
                },
                'ip-172-31-28-113.ap-southeast-2.compute.internal': {
                    'agent_finger_print': '9F:20:AE:4F:1A:4B:D8:8C:ED:D4:27:04:7B:BD:49:97:F2:64:A4:48',
                    'agent_version': '12.0.0.481',
                    'anti_malware': None,
                    'appliance_finger_print': None,
                    'application_control': None,
                    'asset_importance_id': None,
                    'azure_arm_virtual_machine_summary': None,
                    'azure_vm_virtual_machine_summary': None,
                    'bios_uuid': 'ec213c0c-283d-cfc8-c6bf-c878052ea91b',
                    'computer_settings': None,
                    'computer_status': None,
                    'description': '',
                    'display_name': '',
                    'ec2_virtual_machine_summary': None,
                    'esx_summary': None,
                    'firewall': None,
                    'group_id': 0,
                    'host_name': 'ip-172-31-28-113.ap-southeast-2.compute.internal',
                    'id': 2,
                    'integrity_monitoring': None,
                    'interfaces': None,
                    'intrusion_prevention': {
                        'application_type_ids': [74,
                            225,
                            227,
                            257,
                            262,
                            268,
                            287,
                            301,
                            308,
                            327,
                            357,
                            360
                        ],
                        'module_status': {
                            'agent_status': 'active',
                            'agent_status_message': 'On, '
                            'Prevent, '
                            '50 '
                            'rules',
                            'appliance_status': None,
                            'appliance_status_message': None
                        },
                        'rule_ids': [242,
                            459,
                            549,
                            668,
                            1588,
                            1738,
                            2013,
                            2285,
                            2289,
                            2337,
                            2469,
                            2531,
                            2572,
                            2573,
                            2691,
                            2955,
                            2957,
                            3221,
                            3441,
                            3600,
                            3812,
                            3982,
                            3983,
                            3984,
                            3985,
                            3986,
                            4167,
                            4282,
                            4369,
                            4412,
                            4432,
                            4593,
                            4874,
                            4878,
                            5187,
                            5217,
                            5326,
                            5371,
                            5418,
                            5445,
                            5448,
                            5762,
                            5763,
                            5790,
                            5816,
                            5892,
                            6187,
                            6410,
                            6447,
                            6610
                        ],
                        'state': 'prevent'
                    },
                    'last_agent_communication': 1568523742006,
                    'last_appliance_communication': None,
                    'last_ip_used': '192.168.22.2',
                    'last_send_policy_request': 1572997588682,
                    'last_send_policy_success': 1568350165040,
                    'log_inspection': None,
                    'no_connector_virtual_machine_summary': None,
                    'platform': 'Amazon '
                    'Linux 2 (64 '
                    'bit) '
                    '(4.14.123-111.109.amzn2.x86_64)',
                    'policy_id': 9,
                    'relay_list_id': 0,
                    'sap': None,
                    'security_updates': None,
                    'tasks': None,
                    'vcloud_vm_virtual_machine_summary': None,
                    'vmware_vm_virtual_machine_summary': None,
                    'web_reputation': None,
                    'workspace_virtual_machine_summary': None
                }
            }

        Returns:
            dict: Dict of Computers objects
        """

        self.logger.entry('info', 'Obtaining computers...')
        expand = api.Expand(api.Expand.intrusion_prevention)

        try:
            computers_api = api.ComputersApi(self.api_client)
            computer_list = computers_api.list_computers(self.api_version, expand=expand.list(), overrides=False)

        except ApiException as e:
            self.logger.entry('critical', str(e))
            sys.exit(1)

        computers = dict()

        for computer in computer_list.computers:
            computers[computer.host_name] = computer

        num_computers = len(computers)
        self.logger.entry('info', f'Obtained {num_computers} computers')
        self.logger.entry('debug', pformat(computers))

        return computers

    def get_computer(self, hostname) -> api.Computer:
        """Obtain a specific computer

        Examples:
            Output::

            {
                'computers': [{
                    'agent_finger_print': '4F:E3:DD:C1:FD:D1:FB:93:D8:D0:C3:21:69:5A:1C:83:F6:C1:1E:C2',
                    'agent_version': '12.0.0.563',
                    'anti_malware': {
                        'last_manual_scan': None,
                        'last_scheduled_scan': None,
                        'manual_scan_configuration_id': 2,
                        'module_status': {
                            'agent_status': 'inactive',
                            'agent_status_message': 'Off, '
                            'installed',
                            'appliance_status': None,
                            'appliance_status_message': None
                        },
                        'real_time_scan_configuration_id': 1,
                        'real_time_scan_schedule_id': 4,
                        'scheduled_scan_configuration_id': 3,
                        'state': 'off'
                    },
                    'appliance_finger_print': None,
                    'application_control': {
                        'block_unrecognized': False,
                        'maintenance_mode_duration': None,
                        'maintenance_mode_end_time': None,
                        'maintenance_mode_start_time': None,
                        'maintenance_mode_status': 'off',
                        'module_status': {
                            'agent_status': 'inactive',
                            'agent_status_message': 'Off, '
                            'not '
                            'installed',
                            'appliance_status': None,
                            'appliance_status_message': None
                        },
                        'ruleset_id': None,
                        'state': 'off'
                    },
                    'asset_importance_id': None,
                    'azure_arm_virtual_machine_summary': None,
                    'azure_vm_virtual_machine_summary': None,
                    'bios_uuid': 'ec2e87d1-b402-6bff-07f9-1cac94545a1c',
                    'computer_settings': {
                        'anti_malware_setting_behavior_monitoring_scan_exclusion_list': {
                            'value': ''
                        },
                        'anti_malware_setting_combined_mode_protection_source': {
                            'value': 'Appliance '
                            'preferred'
                        },
                        'anti_malware_setting_connected_threat_defense_suspicious_file_ddan_submission_enabled': {
                            'value': 'true'
                        },
                        'anti_malware_setting_connected_threat_defense_use_control_manager_suspicious_object_list_enabled': {
                            'value': 'true'
                        },
                        'anti_malware_setting_document_exploit_protection_rule_exceptions': {
                            'value': ''
                        },
                        'anti_malware_setting_file_hash_enabled': {
                            'value': 'false'
                        },
                        'anti_malware_setting_file_hash_md5_enabled': {
                            'value': 'false'
                        },
                        'anti_malware_setting_file_hash_sha256_enabled': {
                            'value': 'false'
                        },
                        'anti_malware_setting_file_hash_size_max_mbytes': {
                            'value': '128'
                        },
                        'anti_malware_setting_identified_files_space_max_mbytes': {
                            'value': '1024'
                        },
                        'anti_malware_setting_malware_scan_multithreaded_processing_enabled': {
                            'value': 'false'
                        },
                        'anti_malware_setting_nsx_security_tagging_enabled': {
                            'value': 'true'
                        },
                        'anti_malware_setting_nsx_security_tagging_on_remediation_failure_enabled': {
                            'value': 'true'
                        },
                        'anti_malware_setting_nsx_security_tagging_remove_on_clean_scan_enabled': {
                            'value': 'true'
                        },
                        'anti_malware_setting_nsx_security_tagging_value': {
                            'value': 'ANTI_VIRUS.VirusFound.threat=medium'
                        },
                        'anti_malware_setting_predictive_machine_learning_exceptions': {
                            'value': ''
                        },
                        'anti_malware_setting_scan_cache_on_demand_config_id': {
                            'value': '1'
                        },
                        'anti_malware_setting_scan_cache_real_time_config_id': {
                            'value': '2'
                        },
                        'anti_malware_setting_scan_file_size_max_mbytes': {
                            'value': '0'
                        },
                        'anti_malware_setting_smart_protection_global_server_enabled': {
                            'value': 'true'
                        },
                        'anti_malware_setting_smart_protection_global_server_use_proxy_enabled': {
                            'value': 'false'
                        },
                        'anti_malware_setting_smart_protection_local_server_allow_off_domain_global': {
                            'value': 'false'
                        },
                        'anti_malware_setting_smart_protection_local_server_urls': {
                            'value': ''
                        },
                        'anti_malware_setting_smart_protection_server_connection_lost_warning_enabled': {
                            'value': 'true'
                        },
                        'anti_malware_setting_smart_scan_state': {
                            'value': 'Automatic'
                        },
                        'anti_malware_setting_spyware_approved_list': {
                            'value': ''
                        },
                        'anti_malware_setting_syslog_config_id': {
                            'value': '0'
                        },
                        'anti_malware_setting_virtual_appliance_on_demand_scan_cache_entries_max': {
                            'value': '500000'
                        },
                        'anti_malware_setting_virtual_appliance_real_time_scan_cache_entries_max': {
                            'value': '500000'
                        },
                        'application_control_setting_execution_enforcement_level': {
                            'value': 'Allow '
                            'unrecognized '
                            'software '
                            'until '
                            'it '
                            'is '
                            'explicitly '
                            'blocked'
                        },
                        'application_control_setting_ruleset_mode': {
                            'value': 'Use '
                            'local '
                            'ruleset'
                        },
                        'application_control_setting_shared_ruleset_id': {
                            'value': '0'
                        },
                        'application_control_setting_syslog_config_id': {
                            'value': '0'
                        },
                        'firewall_setting_anti_evasion_check_evasive_retransmit': {
                            'value': 'Allow'
                        },
                        'firewall_setting_anti_evasion_check_fin_no_connection': {
                            'value': 'Allow'
                        },
                        'firewall_setting_anti_evasion_check_fragmented_packets': {
                            'value': 'Allow'
                        },
                        'firewall_setting_anti_evasion_check_out_no_connection': {
                            'value': 'Allow'
                        },
                        'firewall_setting_anti_evasion_check_paws': {
                            'value': 'Ignore'
                        },
                        'firewall_setting_anti_evasion_check_rst_no_connection': {
                            'value': 'Allow'
                        },
                        'firewall_setting_anti_evasion_check_tcp_checksum': {
                            'value': 'Allow'
                        },
                        'firewall_setting_anti_evasion_check_tcp_congestion_flags': {
                            'value': 'Allow'
                        },
                        'firewall_setting_anti_evasion_check_tcp_paws_zero': {
                            'value': 'Allow'
                        },
                        'firewall_setting_anti_evasion_check_tcp_rst_fin_flags': {
                            'value': 'Deny'
                        },
                        'firewall_setting_anti_evasion_check_tcp_split_handshake': {
                            'value': 'Deny'
                        },
                        'firewall_setting_anti_evasion_check_tcp_syn_fin_flags': {
                            'value': 'Deny'
                        },
                        'firewall_setting_anti_evasion_check_tcp_syn_rst_flags': {
                            'value': 'Deny'
                        },
                        'firewall_setting_anti_evasion_check_tcp_syn_with_data': {
                            'value': 'Deny'
                        },
                        'firewall_setting_anti_evasion_check_tcp_urgent_flags': {
                            'value': 'Allow'
                        },
                        'firewall_setting_anti_evasion_check_tcp_zero_flags': {
                            'value': 'Deny'
                        },
                        'firewall_setting_anti_evasion_security_posture': {
                            'value': 'Normal'
                        },
                        'firewall_setting_anti_evasion_tcp_paws_window_policy': {
                            'value': '0'
                        },
                        'firewall_setting_combined_mode_protection_source': {
                            'value': 'Agent '
                            'preferred'
                        },
                        'firewall_setting_config_package_exceeds_alert_max_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_ack_timeout': {
                            'value': '1 '
                            'Second'
                        },
                        'firewall_setting_engine_option_allow_null_ip_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_block_ipv6_agent8_and_earlier_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_block_ipv6_agent9_and_later_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_block_same_src_dst_ip_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_boot_start_timeout': {
                            'value': '20 '
                            'Seconds'
                        },
                        'firewall_setting_engine_option_bypass_cisco_waas_connections_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_close_timeout': {
                            'value': '0 '
                            'Seconds'
                        },
                        'firewall_setting_engine_option_close_wait_timeout': {
                            'value': '2 '
                            'Minutes'
                        },
                        'firewall_setting_engine_option_closing_timeout': {
                            'value': '1 '
                            'Second'
                        },
                        'firewall_setting_engine_option_cold_start_timeout': {
                            'value': '5 '
                            'Minutes'
                        },
                        'firewall_setting_engine_option_connection_cleanup_timeout': {
                            'value': '10 '
                            'Seconds'
                        },
                        'firewall_setting_engine_option_connections_cleanup_max': {
                            'value': '1000'
                        },
                        'firewall_setting_engine_option_connections_num_icmp_max': {
                            'value': '10000'
                        },
                        'firewall_setting_engine_option_connections_num_tcp_max': {
                            'value': '10000'
                        },
                        'firewall_setting_engine_option_connections_num_udp_max': {
                            'value': '1000000'
                        },
                        'firewall_setting_engine_option_debug_mode_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_debug_packet_num_max': {
                            'value': '8'
                        },
                        'firewall_setting_engine_option_disconnect_timeout': {
                            'value': '60 '
                            'Seconds'
                        },
                        'firewall_setting_engine_option_drop6_to4_bogons_addresses_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_drop_evasive_retransmit_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_drop_ip_zero_payload_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_drop_ipv6_bogons_addresses_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_drop_ipv6_ext_type0_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_drop_ipv6_fragments_lower_than_min_mtu_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_drop_ipv6_reserved_addresses_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_drop_ipv6_site_local_addresses_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_drop_teredo_anomalies_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_drop_unknown_ssl_protocol_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_error_timeout': {
                            'value': '10 '
                            'Seconds'
                        },
                        'firewall_setting_engine_option_established_timeout': {
                            'value': '3 '
                            'Hours'
                        },
                        'firewall_setting_engine_option_event_nodes_max': {
                            'value': '20000'
                        },
                        'firewall_setting_engine_option_filter_ipv4_tunnels': {
                            'value': 'Disable '
                            'Detection '
                            'of '
                            'IPv4 '
                            'Tunnels'
                        },
                        'firewall_setting_engine_option_filter_ipv6_tunnels': {
                            'value': 'Disable '
                            'Detection '
                            'of '
                            'IPv6 '
                            'Tunnels'
                        },
                        'firewall_setting_engine_option_fin_wait1_timeout': {
                            'value': '2 '
                            'Minutes'
                        },
                        'firewall_setting_engine_option_force_allow_dhcp_dns': {
                            'value': 'Allow '
                            'DNS '
                            'Query '
                            'and '
                            'DHCP '
                            'Client'
                        },
                        'firewall_setting_engine_option_force_allow_icmp_type3_code4': {
                            'value': 'Add '
                            'Force '
                            'Allow '
                            'rule '
                            'for '
                            'ICMP '
                            'type3 '
                            'code4'
                        },
                        'firewall_setting_engine_option_fragment_offset_min': {
                            'value': '60'
                        },
                        'firewall_setting_engine_option_fragment_size_min': {
                            'value': '120'
                        },
                        'firewall_setting_engine_option_generate_connection_events_icmp_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_generate_connection_events_tcp_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_generate_connection_events_udp_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_icmp_timeout': {
                            'value': '60 '
                            'Seconds'
                        },
                        'firewall_setting_engine_option_ignore_status_code0': {
                            'value': 'None'
                        },
                        'firewall_setting_engine_option_ignore_status_code1': {
                            'value': 'None'
                        },
                        'firewall_setting_engine_option_ignore_status_code2': {
                            'value': 'None'
                        },
                        'firewall_setting_engine_option_last_ack_timeout': {
                            'value': '3 '
                            'Minutes'
                        },
                        'firewall_setting_engine_option_log_all_packet_data_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_log_events_per_second_max': {
                            'value': '100'
                        },
                        'firewall_setting_engine_option_log_one_packet_period': {
                            'value': '5 '
                            'Minutes'
                        },
                        'firewall_setting_engine_option_log_one_packet_within_period_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_log_packet_length_max': {
                            'value': '1500 '
                            'Bytes'
                        },
                        'firewall_setting_engine_option_logging_policy': {
                            'value': 'Default'
                        },
                        'firewall_setting_engine_option_silent_tcp_connection_drop_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_option_ssl_session_size': {
                            'value': 'Low '
                            '- '
                            '2500'
                        },
                        'firewall_setting_engine_option_ssl_session_time': {
                            'value': '24 '
                            'Hours'
                        },
                        'firewall_setting_engine_option_strict_terodo_port_check_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_engine_option_syn_rcvd_timeout': {
                            'value': '60 '
                            'Seconds'
                        },
                        'firewall_setting_engine_option_syn_sent_timeout': {
                            'value': '20 '
                            'Seconds'
                        },
                        'firewall_setting_engine_option_tcp_mss_limit': {
                            'value': 'No '
                            'Limit'
                        },
                        'firewall_setting_engine_option_tunnel_depth_max': {
                            'value': '1'
                        },
                        'firewall_setting_engine_option_tunnel_depth_max_exceeded_action': {
                            'value': 'Drop'
                        },
                        'firewall_setting_engine_option_udp_timeout': {
                            'value': '20 '
                            'Seconds'
                        },
                        'firewall_setting_engine_option_verify_tcp_checksum_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_engine_options_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_event_log_file_cached_entries_life_time': {
                            'value': '30 '
                            'Minutes'
                        },
                        'firewall_setting_event_log_file_cached_entries_num': {
                            'value': '128'
                        },
                        'firewall_setting_event_log_file_cached_entries_stale_time': {
                            'value': '15 '
                            'Minutes'
                        },
                        'firewall_setting_event_log_file_ignore_source_ip_list_id': {
                            'value': ''
                        },
                        'firewall_setting_event_log_file_retain_num': {
                            'value': '3'
                        },
                        'firewall_setting_event_log_file_size_max': {
                            'value': '4 '
                            'MB'
                        },
                        'firewall_setting_events_out_of_allowed_policy_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_failure_response_engine_system': {
                            'value': 'Fail '
                            'closed'
                        },
                        'firewall_setting_failure_response_packet_sanity_check': {
                            'value': 'Fail '
                            'closed'
                        },
                        'firewall_setting_interface_isolation_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_interface_limit_one_active_enabled': {
                            'value': 'false'
                        },
                        'firewall_setting_interface_patterns': {
                            'value': ''
                        },
                        'firewall_setting_network_engine_mode': {
                            'value': 'Inline'
                        },
                        'firewall_setting_reconnaissance_block_fingerprint_probe_duration': {
                            'value': 'No'
                        },
                        'firewall_setting_reconnaissance_block_network_or_port_scan_duration': {
                            'value': 'No'
                        },
                        'firewall_setting_reconnaissance_block_tcp_null_scan_duration': {
                            'value': 'No'
                        },
                        'firewall_setting_reconnaissance_block_tcp_syn_fin_scan_duration': {
                            'value': 'No'
                        },
                        'firewall_setting_reconnaissance_block_tcp_xmas_attack_duration': {
                            'value': 'No'
                        },
                        'firewall_setting_reconnaissance_detect_fingerprint_probe_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_detect_network_or_port_scan_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_detect_tcp_null_scan_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_detect_tcp_syn_fin_scan_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_detect_tcp_xmas_attack_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_exclude_ip_list_id': {
                            'value': '1'
                        },
                        'firewall_setting_reconnaissance_include_ip_list_id': {
                            'value': ''
                        },
                        'firewall_setting_reconnaissance_notify_fingerprint_probe_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_notify_network_or_port_scan_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_notify_tcp_null_scan_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_notify_tcp_syn_fin_scan_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_reconnaissance_notify_tcp_xmas_attack_enabled': {
                            'value': 'true'
                        },
                        'firewall_setting_virtual_and_container_network_scan_enabled': {
                            'value': 'false'
                        },
                        'integrity_monitoring_setting_auto_apply_recommendations_enabled': {
                            'value': 'No'
                        },
                        'integrity_monitoring_setting_combined_mode_protection_source': {
                            'value': 'Appliance '
                            'preferred'
                        },
                        'integrity_monitoring_setting_content_hash_algorithm': {
                            'value': 'sha1'
                        },
                        'integrity_monitoring_setting_cpu_usage_level': {
                            'value': 'High'
                        },
                        'integrity_monitoring_setting_realtime_enabled': {
                            'value': 'false'
                        },
                        'integrity_monitoring_setting_scan_cache_config_id': {
                            'value': '3'
                        },
                        'integrity_monitoring_setting_syslog_config_id': {
                            'value': '0'
                        },
                        'integrity_monitoring_setting_virtual_appliance_optimization_scan_cache_entries_max': {
                            'value': '500000'
                        },
                        'intrusion_prevention_setting_auto_apply_recommendations_enabled': {
                            'value': 'Yes'
                        },
                        'intrusion_prevention_setting_combined_mode_protection_source': {
                            'value': 'Agent '
                            'preferred'
                        },
                        'intrusion_prevention_setting_engine_option_fragmented_ip_keep_max': {
                            'value': '1000'
                        },
                        'intrusion_prevention_setting_engine_option_fragmented_ip_packet_send_icmp_enabled': {
                            'value': 'true'
                        },
                        'intrusion_prevention_setting_engine_option_fragmented_ip_timeout': {
                            'value': '60 '
                            'Seconds'
                        },
                        'intrusion_prevention_setting_engine_option_fragmented_ip_unconcerned_mac_address_bypass_enabled': {
                            'value': 'false'
                        },
                        'intrusion_prevention_setting_engine_options_enabled': {
                            'value': 'false'
                        },
                        'intrusion_prevention_setting_log_data_rule_first_match_enabled': {
                            'value': 'true'
                        },
                        'intrusion_prevention_setting_nsx_security_tagging_detect_mode_level': {
                            'value': 'No '
                            'Tagging'
                        },
                        'intrusion_prevention_setting_nsx_security_tagging_prevent_mode_level': {
                            'value': 'No '
                            'Tagging'
                        },
                        'intrusion_prevention_setting_virtual_and_container_network_scan_enabled': {
                            'value': 'true'
                        },
                        'log_inspection_setting_auto_apply_recommendations_enabled': {
                            'value': 'No'
                        },
                        'log_inspection_setting_severity_clipping_agent_event_send_syslog_level_min': {
                            'value': 'Medium '
                            '(6)'
                        },
                        'log_inspection_setting_severity_clipping_agent_event_store_level_min': {
                            'value': 'Medium '
                            '(6)'
                        },
                        'log_inspection_setting_syslog_config_id': {
                            'value': '0'
                        },
                        'platform_setting_agent_communications_direction': {
                            'value': 'Agent/Appliance '
                            'Initiated'
                        },
                        'platform_setting_agent_events_send_interval': {
                            'value': '60 '
                            'Seconds'
                        },
                        'platform_setting_agent_self_protection_enabled': {
                            'value': 'false'
                        },
                        'platform_setting_agent_self_protection_password': {
                            'value': ''
                        },
                        'platform_setting_agent_self_protection_password_enabled': {
                            'value': 'false'
                        },
                        'platform_setting_auto_assign_new_intrusion_prevention_rules_enabled': {
                            'value': 'true'
                        },
                        'platform_setting_auto_update_anti_malware_engine_enabled': {
                            'value': 'false'
                        },
                        'platform_setting_combined_mode_network_group_protection_source': {
                            'value': 'Agent '
                            'preferred'
                        },
                        'platform_setting_environment_variable_overrides': {
                            'value': ''
                        },
                        'platform_setting_heartbeat_inactive_vm_offline_alert_enabled': {
                            'value': 'false'
                        },
                        'platform_setting_heartbeat_interval': {
                            'value': '10 '
                            'Minutes'
                        },
                        'platform_setting_heartbeat_local_time_shift_alert_threshold': {
                            'value': 'Unlimited'
                        },
                        'platform_setting_heartbeat_missed_alert_threshold': {
                            'value': '5'
                        },
                        'platform_setting_inactive_agent_cleanup_override_enabled': {
                            'value': 'false'
                        },
                        'platform_setting_notifications_suppress_popups_enabled': {
                            'value': 'false'
                        },
                        'platform_setting_recommendation_ongoing_scans_interval': {
                            'value': '7 '
                            'Days'
                        },
                        'platform_setting_relay_state': {
                            'value': 'false'
                        },
                        'platform_setting_scan_cache_concurrency_max': {
                            'value': '1'
                        },
                        'platform_setting_scan_open_port_list_id': {
                            'value': '1-1024'
                        },
                        'platform_setting_smart_protection_anti_malware_global_server_proxy_id': {
                            'value': ''
                        },
                        'platform_setting_smart_protection_global_server_enabled': {
                            'value': 'true'
                        },
                        'platform_setting_smart_protection_global_server_proxy_id': {
                            'value': ''
                        },
                        'platform_setting_smart_protection_global_server_use_proxy_enabled': {
                            'value': 'false'
                        },
                        'platform_setting_troubleshooting_logging_level': {
                            'value': 'Do '
                            'Not '
                            'Override'
                        },
                        'platform_setting_upgrade_on_activation_enabled': {
                            'value': 'false'
                        },
                        'web_reputation_setting_alerting_enabled': {
                            'value': 'false'
                        },
                        'web_reputation_setting_allowed_url_domains': {
                            'value': ''
                        },
                        'web_reputation_setting_allowed_urls': {
                            'value': ''
                        },
                        'web_reputation_setting_blocked_url_domains': {
                            'value': ''
                        },
                        'web_reputation_setting_blocked_url_keywords': {
                            'value': ''
                        },
                        'web_reputation_setting_blocked_urls': {
                            'value': ''
                        },
                        'web_reputation_setting_blocking_page_link': {
                            'value': 'http://sitesafety.trendmicro.com/'
                        },
                        'web_reputation_setting_combined_mode_protection_source': {
                            'value': 'Agent '
                            'preferred'
                        },
                        'web_reputation_setting_monitor_port_list_id': {
                            'value': '80,8080'
                        },
                        'web_reputation_setting_security_block_untested_pages_enabled': {
                            'value': 'false'
                        },
                        'web_reputation_setting_security_level': {
                            'value': 'Medium'
                        },
                        'web_reputation_setting_smart_protection_global_server_use_proxy_enabled': {
                            'value': 'false'
                        },
                        'web_reputation_setting_smart_protection_local_server_allow_off_domain_global': {
                            'value': 'false'
                        },
                        'web_reputation_setting_smart_protection_local_server_enabled': {
                            'value': 'false'
                        },
                        'web_reputation_setting_smart_protection_local_server_urls': {
                            'value': ''
                        },
                        'web_reputation_setting_smart_protection_server_connection_lost_warning_enabled': {
                            'value': 'true'
                        },
                        'web_reputation_setting_smart_protection_web_reputation_global_server_proxy_id': {
                            'value': ''
                        },
                        'web_reputation_setting_syslog_config_id': {
                            'value': '0'
                        }
                    },
                    'computer_status': {
                        'agent_status': 'error',
                        'agent_status_messages': ['Offline',
                            'Integrity '
                            'Monitoring Rule '
                            'Compile Issue'
                        ],
                        'appliance_status': None,
                        'appliance_status_messages': None
                    },
                    'description': '',
                    'display_name': '',
                    'ec2_virtual_machine_summary': None,
                    'esx_summary': None,
                    'firewall': {
                        'global_stateful_configuration_id': 1,
                        'module_status': {
                            'agent_status': 'inactive',
                            'agent_status_message': 'Off, '
                            'installed, '
                            '2 '
                            'rules',
                            'appliance_status': None,
                            'appliance_status_message': None
                        },
                        'rule_ids': [23, 28],
                        'state': 'off',
                        'stateful_configuration_assignments': {
                            'stateful_configuration_assignments': [{
                                'interface_id': 34,
                                'interface_type_id': None,
                                'stateful_configuration_id': 1
                            }]
                        }
                    },
                    'group_id': 0,
                    'host_name': 'WIN-Q0HITV3HJ6D',
                    'id': 34,
                    'integrity_monitoring': {
                        'last_baseline_created': 1569386473746,
                        'last_integrity_scan': None,
                        'module_status': {
                            'agent_status': 'error',
                            'agent_status_message': 'Integrity '
                            'Monitoring '
                            'Rule '
                            'Compile '
                            'Issue',
                            'appliance_status': None,
                            'appliance_status_message': None
                        },
                        'rule_ids': None,
                        'state': 'off'
                    },
                    'interfaces': {
                        'interfaces': [{
                            'detected': True,
                            'dhcp': True,
                            'display_name': '',
                            'id': 34,
                            'interface_type_id': None,
                            'ips': None,
                            'mac': '02:07:83:A8:4C:1A',
                            'name': 'Local Area Connection '
                            '3'
                        }]
                    },
                    'intrusion_prevention': {
                        'application_type_ids': [117,
                            243,
                            268,
                            287,
                            299,
                            300,
                            301,
                            303,
                            304,
                            340,
                            352
                        ],
                        'module_status': {
                            'agent_status': 'inactive',
                            'agent_status_message': 'Off, '
                            'installed, '
                            '32 '
                            'rules',
                            'appliance_status': None,
                            'appliance_status_message': None
                        },
                        'rule_ids': [2013,
                            2285,
                            2302,
                            3218,
                            3441,
                            3600,
                            3812,
                            4167,
                            4282,
                            4432,
                            4456,
                            4458,
                            4459,
                            4460,
                            4461,
                            5400,
                            5403,
                            5762,
                            5763,
                            6281,
                            6282,
                            6298,
                            6308,
                            6378,
                            6379,
                            6419,
                            6425,
                            6676,
                            6699,
                            6700,
                            6774,
                            7007
                        ],
                        'state': 'off'
                    },
                    'last_agent_communication': 1569411611641,
                    'last_appliance_communication': None,
                    'last_ip_used': '192.168.22.2',
                    'last_send_policy_request': 1573101479760,
                    'last_send_policy_success': 1569386473666,
                    'log_inspection': {
                        'module_status': {
                            'agent_status': 'inactive',
                            'agent_status_message': 'Off, '
                            'installed, '
                            'no '
                            'rules',
                            'appliance_status': None,
                            'appliance_status_message': None
                        },
                        'rule_ids': None,
                        'state': 'off'
                    },
                    'no_connector_virtual_machine_summary': {
                        'account_id': '686616308178',
                        'directory_id': None,
                        'instance_id': 'i-05767245e59a59bec',
                        'region': 'ap-southeast-2',
                        'user_name': None
                    },
                    'platform': 'Microsoft Windows Server 2008 R2 (64 bit) Service '
                    'Pack 1 Build 7601',
                    'policy_id': 54,
                    'relay_list_id': 0,
                    'sap': None,
                    'security_updates': {
                        'anti_malware': [{
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Advanced '
                                'Threat '
                                'Correlation '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '1.121.00'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Advanced '
                                'Threat Scan '
                                'Engine',
                                'platform': 'Windows '
                                '64-bit',
                                'version': '11.000.1006'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Behavior '
                                'Monitoring '
                                'Configuration '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '1.237.00'
                            },
                            {
                                'for_use_by': None,
                                'latest': False,
                                'name': 'Behavior '
                                'Monitoring '
                                'Detection '
                                'Pattern',
                                'platform': 'Windows '
                                '64-bit',
                                'version': '1.941.64'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Contextual '
                                'Intelligence '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '102800'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Damage Cleanup '
                                'Engine '
                                'Configuration',
                                'platform': 'All '
                                'Platforms',
                                'version': '16.1'
                            },
                            {
                                'for_use_by': None,
                                'latest': False,
                                'name': 'Damage Cleanup '
                                'Template',
                                'platform': 'All '
                                'Platforms',
                                'version': '1602'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Damage '
                                'Recovery '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '1.7.2'
                            },
                            {
                                'for_use_by': None,
                                'latest': False,
                                'name': 'Digital '
                                'Signature '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '1.721.00'
                            },
                            {
                                'for_use_by': None,
                                'latest': False,
                                'name': 'Endpoint '
                                'Sensor Trusted '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '271058'
                            },
                            {
                                'for_use_by': None,
                                'latest': False,
                                'name': 'IntelliTrap '
                                'Exception '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '1.647.00'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'IntelliTrap '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '0.251.00'
                            },
                            {
                                'for_use_by': None,
                                'latest': False,
                                'name': 'Memory '
                                'Inspection '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '1.521.00'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Memory Scan '
                                'Trigger '
                                'Pattern',
                                'platform': 'Windows '
                                '64-bit',
                                'version': '1364'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Platform '
                                'Configuration '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '5.5.1000'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Policy '
                                'Enforcement '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '1.246.00'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Real-time Scan '
                                'Flow Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '200005'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Scan Exception '
                                'Local Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '110000'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Scan Exception '
                                'OEM Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '110300'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'Scan Exception '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '110100'
                            },
                            {
                                'for_use_by': None,
                                'latest': False,
                                'name': 'Smart Scan '
                                'Agent Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '15.385.00'
                            },
                            {
                                'for_use_by': None,
                                'latest': False,
                                'name': 'Spyware/Grayware '
                                'Pattern',
                                'platform': 'All '
                                'Platforms',
                                'version': '22.15'
                            },
                            {
                                'for_use_by': None,
                                'latest': True,
                                'name': 'System Driver '
                                'Configuration',
                                'platform': 'All '
                                'Platforms',
                                'version': '8.11.1028'
                            },
                            {
                                'for_use_by': None,
                                'latest': False,
                                'name': 'Threat Tracing '
                                'Pattern',
                                'platform': 'Windows '
                                '64-bit',
                                'version': '130764'
                            }
                        ],
                        'last_changed': 1569399656226,
                        'manifests': None,
                        'other': None,
                        'rules': None,
                        'update_status': {
                            'status': 'warning',
                            'status_message': 'Out-of-Date'
                        },
                        'web_reputation_service': None
                    },
                    'tasks': {
                        'agent_tasks': ['Update of Configuration Pending '
                            '(Offline)'
                        ],
                        'appliance_tasks': None
                    },
                    'vcloud_vm_virtual_machine_summary': None,
                    'vmware_vm_virtual_machine_summary': None,
                    'web_reputation': {
                        'module_status': {
                            'agent_status': 'inactive',
                            'agent_status_message': 'Off, '
                            'installed',
                            'appliance_status': None,
                            'appliance_status_message': None
                        },
                        'state': 'off'
                    },
                    'workspace_virtual_machine_summary': None
                }]
            }

        Returns:
            Computers object
        """

        self.logger.entry('info', f'Searching for "{hostname}" IDs...')

        search_field = 'hostName'
        search_computers_api = api.ComputersApi(self.api_client).search_computers
        result = self._find_exact_match(search_field, hostname, search_computers_api)

        try:
            computer = result.computers[0]

        except IndexError:
            raise ValueError(f'Computer "{hostname}" cannot be found in Deep Security')

        return computer

    def get_ips_rules(self) -> dict:
        """IPS rule map with Rule ID as key

        Examples:
            Output::

            {
                6367: {
                    'action': None,
                    'alert_enabled': False,
                    'always_include_packet_data': False,
                    'application_type_id': 261,
                    'can_be_assigned_alone': True,
                    'case_sensitive': None,
                    'condition': None,
                    'context_id': None,
                    'custom_xml': None,
                    'cve': ['CVE-2008-2938',
                        'CVE-2017-8980',
                        'CVE-2018-6220',
                        'CVE-2018-6660',
                        'CVE-2018-1271',
                        'CVE-2017-8944',
                        'CVE-2017-1000028',
                        'CVE-2018-14007',
                        'CVE-2017-2595',
                        'CVE-2014-3578',
                        'CVE-2016-9878',
                        'CVE-2014-3625'
                    ],
                    'cvss_score': '10.00',
                    'debug_mode_enabled': False,
                    'depends_on_rule_ids': [5892],
                    'description': 'Directory traversal is an attack technique that allows an '
                    'attacker to traverse one or more forbidden directories to '
                    'gain access to restricted files. Such attacks are a result of '
                    'improper validation/configuration by either the programmer or '
                    'the server itself. This rule is intended to detect directory '
                    'traversal sequences in the URI.',
                    'detect_only': True,
                    'end': None,
                    'event_logging_disabled': False,
                    'generate_event_on_packet_drop': True,
                    'id': 6367,
                    'identifier': '1009040',
                    'last_updated': 1538464980000,
                    'minimum_agent_version': None,
                    'name': 'Identified Directory Traversal Sequence In URI',
                    'original_issue': 1524560700000,
                    'patterns': None,
                    'priority': 'normal',
                    'recommendations_mode': None,
                    'schedule_id': None,
                    'severity': 'critical',
                    'signature': None,
                    'start': None,
                    'template': None,
                    'type': 'smart'
                },
                6368: {
                    'action': None,
                    'alert_enabled': False,
                    'always_include_packet_data': False,
                    'application_type_id': 287,
                    'can_be_assigned_alone': True,
                    'case_sensitive': None,
                    'condition': None,
                    'context_id': None,
                    'custom_xml': None,
                    'cve': ['CVE-2018-11624'],
                    'cvss_score': '6.80',
                    'debug_mode_enabled': False,
                    'depends_on_rule_ids': [4282],
                    'description': 'ImageMagick is prone to a denial-of-service vulnerability. An '
                    'attacker can exploit this issue to crash the affected '
                    'application, resulting in denial-of-service conditions.',
                    'detect_only': False,
                    'end': None,
                    'event_logging_disabled': False,
                    'generate_event_on_packet_drop': True,
                    'id': 6368,
                    'identifier': '1009318',
                    'last_updated': 1553010360000,
                    'minimum_agent_version': None,
                    'name': "ImageMagick 'ReadMATImage' Use After Free Vulnerability "
                    '(CVE-2018-11624)',
                    'original_issue': 1553010360000,
                    'patterns': None,
                    'priority': 'normal',
                    'recommendations_mode': 'enabled',
                    'schedule_id': None,
                    'severity': 'medium',
                    'signature': None,
                    'start': None,
                    'template': None,
                    'type': 'exploit'
                }
            }

        Returns:
            dict: IPS rule ID to IPS rule map
            """

        self.logger.entry('info', 'Obtaining IPS rules...')
        ips_rules = dict()
        search_criteria = api.SearchCriteria()
        search_criteria.id_value = 0
        search_criteria.id_test = 'greater-than'

        search_filter = api.SearchFilter()
        search_filter.max_items = PAGE_SIZE
        search_filter.search_criteria = [search_criteria]

        ips_api = api.IntrusionPreventionRulesApi(self.api_client)

        while True:
            try:
                rule_list = ips_api.search_intrusion_prevention_rules(self.api_version, search_filter=search_filter)
                num_found = len(rule_list.intrusion_prevention_rules)

                self.logger.entry('info', f'Found {num_found} rules')

            except ApiException as e:
                self.logger.entry('critical', str(e))
                sys.exit(1)

            for rule in rule_list.intrusion_prevention_rules:
                ips_rules[rule.id] = rule

            last_id = rule_list.intrusion_prevention_rules[-1].id
            search_criteria.id_value = last_id

            if num_found < PAGE_SIZE:
                break

        num_ips_rules = len(ips_rules)
        self.logger.entry('info', f'Total IPS rules found: {num_ips_rules}')
        self.logger.entry('debug', pformat(ips_rules))

        return ips_rules

    @staticmethod
    def epoch_to_timestamp(epoch_time):
        epoch_strip = str(epoch_time)[:-3]
        epoch = int(epoch_strip)

        return time.strftime('%d/%m/%Y, %H:%M:%S %Z', time.localtime(epoch))

    def generate_csv(self, report_entries, filename):
        with open(filename, 'w') as f:
            columns = list(report_entries[0].keys())
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for row in report_entries:
                writer.writerow(row)

        self.logger.entry('info', 'Done')

    @staticmethod
    def _get_env_var(env_var, default):
        '''Required as Docker passes in a blank string if env vars are not specified. os.environ.get sees it as valid
        input and therefore does not fall back to the default option'''

        env_var_value = os.environ.get(env_var)

        # if empty string or None
        if env_var_value:
            return env_var_value

        else:
            return default

    def _db_setup(self):
        self.logger.entry('info', 'Database output enabled. Extracting database details...')
        try:
            default_db_hostname = f'{self.app_name}-mysql'
            db_hostname = self._get_env_var('DS_DB_HOSTNAME', default_db_hostname)
            self.logger.entry('info', f'Obtained hostname: {db_hostname}')
            db_name = self._get_env_var('DS_DB_NAME', self.app_name)
            self.logger.entry('info', f'Obtained database name: {db_name}')
            db_username = self._get_env_var('DS_DB_USERNAME', 'root')
            self.logger.entry('info', f'Obtained database username: {db_username}')
            db_password = os.environ['DS_DB_PASSWORD']
            self.logger.entry('info', 'Obtained database password: <hidden>')

            try:
                self.db = SetupDb(db_name, db_username, db_password, db_hostname, self.logger)
                self.table = self.db.get_table()
                self.session = self.db.get_session()
                self.logger.entry('info', 'Obtained database table & session')

            except Exception as e:
                msg = f'Could not connect to database - {str(e)}'
                self.logger.entry('critical', msg)
                sys.exit(1)

        except KeyError:
            msg = f'Required database environment variable(s) not provided'
            self.logger.entry('critical', msg)
            sys.exit(1)

    def get_cve_ips_map(self, ips_rules) -> dict:
        """Obtain a CVE to IPS rule map with CVE as key

        Takes `get_ips_rules()` output and creates a CVE to IPS rule map

        Examples:
            Output::

            {
                'CVE-2019-9511': [6917, 7004],
                'CVE-2019-9512': [6917, 6927],
                'CVE-2019-9513': [6917, 6998],
                'CVE-2019-9518': [6917],
                'CVE-2019-9624': [6941],
                'CVE-2019-9640': [7163],
                'CVE-2019-9851': [7100],
                'CVE-2019-9911': [4783],
                'CVE-2019-9912': [4783],
                'CVE-2019-9913': [4783],
                'CVE-2019-9914': [4783],
                'CVE-2019-9978': [6650]
            }

         Returns:
            dict: CVE to IPS rule map
        """
        self.logger.entry('info', f'Mapping CVEs to IPS rules')
        cve_map = dict()

        for ips_id, ips_info in ips_rules.items():
            cves = ips_info.cve

            if not cves:
                continue

            for cve in cves:
                if cve not in cve_map:
                    cve_map[cve] = [ips_id]

                else:
                    cve_map[cve].append(ips_id)

        self.logger.entry('debug', pformat(cve_map))
        return cve_map

    def _find_exact_match(self, search_field, search_string, object_api):
        """Finds an exact match of an object and returns it

        For example, searching for a `Policy` name will return a `Policies` object"""

        search_criteria = api.SearchCriteria()
        search_criteria.field_name = search_field
        search_criteria.string_test = 'equal'
        search_criteria.string_value = search_string

        search_filter = api.SearchFilter(None, [search_criteria])
        search_filter.max_items = 1

        try:
            result = object_api(self.api_version, search_filter=search_filter)

            return result

        except ApiException as e:
            self.logger.entry('critical', str(e))
            sys.exit(1)

    def get_policy(self, policy_name) -> api.Policy:
        """Obtains a policy

        Examples:
            Output::

            {
                'anti_malware': {
                    'manual_scan_configuration_id': 2,
                    'module_status': {
                        'status': 'inactive',
                        'status_message': 'Off'
                    },
                    'real_time_scan_configuration_id': 1,
                    'real_time_scan_schedule_id': 4,
                    'scheduled_scan_configuration_id': 3,
                    'state': 'off'
                },
                'application_control': {
                    'block_unrecognized': None,
                    'module_status': {
                        'status': 'inactive',
                        'status_message': 'Off'
                    },
                    'ruleset_id': None,
                    'state': 'off'
                },
                'auto_requires_update': 'on',
                'description': 'Demo Policy4353 policy',
                'firewall': {
                    'global_stateful_configuration_id': 1,
                    'module_status': {
                        'status': 'inactive',
                        'status_message': 'Off, 2 rules'
                    },
                    'rule_ids': [23, 28],
                    'state': 'off',
                    'stateful_configuration_assignments': None
                },
                'id': 200,
                'integrity_monitoring': {
                    'module_status': {
                        'status': 'inactive',
                        'status_message': 'Off, no rules'
                    },
                    'rule_ids': None,
                    'state': 'off'
                },
                'interface_types': None,
                'intrusion_prevention': {
                    'application_type_ids': [268, 300],
                    'module_status': {
                        'status': 'inactive',
                        'status_message': 'Off, 2 rules'
                    },
                    'rule_ids': [3218, 5762],
                    'state': 'off'
                },
                'log_inspection': {
                    'module_status': {
                        'status': 'inactive',
                        'status_message': 'Off, no rules'
                    },
                    'rule_ids': None,
                    'state': 'off'
                },
                'name': 'Demo Policy4353',
                'parent_id': 1,
                'policy_settings': {
                    'anti_malware_setting_behavior_monitoring_scan_exclusion_list': {
                        'value': ''
                    },
                    'anti_malware_setting_combined_mode_protection_source': {
                        'value': 'Appliance '
                        'preferred'
                    },
                    'anti_malware_setting_connected_threat_defense_suspicious_file_ddan_submission_enabled': {
                        'value': 'true'
                    },
                    'anti_malware_setting_connected_threat_defense_use_control_manager_suspicious_object_list_enabled': {
                        'value': 'true'
                    },
                    'anti_malware_setting_document_exploit_protection_rule_exceptions': {
                        'value': ''
                    },
                    'anti_malware_setting_file_hash_enabled': {
                        'value': 'false'
                    },
                    'anti_malware_setting_file_hash_md5_enabled': {
                        'value': 'false'
                    },
                    'anti_malware_setting_file_hash_sha256_enabled': {
                        'value': 'false'
                    },
                    'anti_malware_setting_file_hash_size_max_mbytes': {
                        'value': '128'
                    },
                    'anti_malware_setting_identified_files_space_max_mbytes': {
                        'value': '1024'
                    },
                    'anti_malware_setting_malware_scan_multithreaded_processing_enabled': {
                        'value': 'false'
                    },
                    'anti_malware_setting_nsx_security_tagging_enabled': {
                        'value': 'true'
                    },
                    'anti_malware_setting_nsx_security_tagging_on_remediation_failure_enabled': {
                        'value': 'true'
                    },
                    'anti_malware_setting_nsx_security_tagging_remove_on_clean_scan_enabled': {
                        'value': 'true'
                    },
                    'anti_malware_setting_nsx_security_tagging_value': {
                        'value': 'ANTI_VIRUS.VirusFound.threat=medium'
                    },
                    'anti_malware_setting_predictive_machine_learning_exceptions': {
                        'value': ''
                    },
                    'anti_malware_setting_scan_cache_on_demand_config_id': {
                        'value': '1'
                    },
                    'anti_malware_setting_scan_cache_real_time_config_id': {
                        'value': '2'
                    },
                    'anti_malware_setting_scan_file_size_max_mbytes': {
                        'value': '0'
                    },
                    'anti_malware_setting_smart_protection_global_server_enabled': {
                        'value': 'true'
                    },
                    'anti_malware_setting_smart_protection_global_server_use_proxy_enabled': {
                        'value': 'false'
                    },
                    'anti_malware_setting_smart_protection_local_server_allow_off_domain_global': {
                        'value': 'false'
                    },
                    'anti_malware_setting_smart_protection_local_server_urls': {
                        'value': ''
                    },
                    'anti_malware_setting_smart_protection_server_connection_lost_warning_enabled': {
                        'value': 'true'
                    },
                    'anti_malware_setting_smart_scan_state': {
                        'value': 'Automatic'
                    },
                    'anti_malware_setting_spyware_approved_list': {
                        'value': ''
                    },
                    'anti_malware_setting_syslog_config_id': {
                        'value': '0'
                    },
                    'anti_malware_setting_virtual_appliance_on_demand_scan_cache_entries_max': {
                        'value': '500000'
                    },
                    'anti_malware_setting_virtual_appliance_real_time_scan_cache_entries_max': {
                        'value': '500000'
                    },
                    'application_control_setting_execution_enforcement_level': {
                        'value': 'Allow '
                        'unrecognized '
                        'software '
                        'until '
                        'it '
                        'is '
                        'explicitly '
                        'blocked'
                    },
                    'application_control_setting_ruleset_mode': {
                        'value': 'Use '
                        'local '
                        'ruleset'
                    },
                    'application_control_setting_shared_ruleset_id': {
                        'value': '0'
                    },
                    'application_control_setting_syslog_config_id': {
                        'value': '0'
                    },
                    'firewall_setting_anti_evasion_check_evasive_retransmit': {
                        'value': 'Allow'
                    },
                    'firewall_setting_anti_evasion_check_fin_no_connection': {
                        'value': 'Allow'
                    },
                    'firewall_setting_anti_evasion_check_fragmented_packets': {
                        'value': 'Allow'
                    },
                    'firewall_setting_anti_evasion_check_out_no_connection': {
                        'value': 'Allow'
                    },
                    'firewall_setting_anti_evasion_check_paws': {
                        'value': 'Ignore'
                    },
                    'firewall_setting_anti_evasion_check_rst_no_connection': {
                        'value': 'Allow'
                    },
                    'firewall_setting_anti_evasion_check_tcp_checksum': {
                        'value': 'Allow'
                    },
                    'firewall_setting_anti_evasion_check_tcp_congestion_flags': {
                        'value': 'Allow'
                    },
                    'firewall_setting_anti_evasion_check_tcp_paws_zero': {
                        'value': 'Allow'
                    },
                    'firewall_setting_anti_evasion_check_tcp_rst_fin_flags': {
                        'value': 'Deny'
                    },
                    'firewall_setting_anti_evasion_check_tcp_split_handshake': {
                        'value': 'Deny'
                    },
                    'firewall_setting_anti_evasion_check_tcp_syn_fin_flags': {
                        'value': 'Deny'
                    },
                    'firewall_setting_anti_evasion_check_tcp_syn_rst_flags': {
                        'value': 'Deny'
                    },
                    'firewall_setting_anti_evasion_check_tcp_syn_with_data': {
                        'value': 'Deny'
                    },
                    'firewall_setting_anti_evasion_check_tcp_urgent_flags': {
                        'value': 'Allow'
                    },
                    'firewall_setting_anti_evasion_check_tcp_zero_flags': {
                        'value': 'Deny'
                    },
                    'firewall_setting_anti_evasion_security_posture': {
                        'value': 'Normal'
                    },
                    'firewall_setting_anti_evasion_tcp_paws_window_policy': {
                        'value': '0'
                    },
                    'firewall_setting_combined_mode_protection_source': {
                        'value': 'Agent '
                        'preferred'
                    },
                    'firewall_setting_config_package_exceeds_alert_max_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_ack_timeout': {
                        'value': '1 '
                        'Second'
                    },
                    'firewall_setting_engine_option_allow_null_ip_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_block_ipv6_agent8_and_earlier_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_block_ipv6_agent9_and_later_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_block_same_src_dst_ip_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_boot_start_timeout': {
                        'value': '20 '
                        'Seconds'
                    },
                    'firewall_setting_engine_option_bypass_cisco_waas_connections_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_close_timeout': {
                        'value': '0 '
                        'Seconds'
                    },
                    'firewall_setting_engine_option_close_wait_timeout': {
                        'value': '2 '
                        'Minutes'
                    },
                    'firewall_setting_engine_option_closing_timeout': {
                        'value': '1 '
                        'Second'
                    },
                    'firewall_setting_engine_option_cold_start_timeout': {
                        'value': '5 '
                        'Minutes'
                    },
                    'firewall_setting_engine_option_connection_cleanup_timeout': {
                        'value': '10 '
                        'Seconds'
                    },
                    'firewall_setting_engine_option_connections_cleanup_max': {
                        'value': '1000'
                    },
                    'firewall_setting_engine_option_connections_num_icmp_max': {
                        'value': '10000'
                    },
                    'firewall_setting_engine_option_connections_num_tcp_max': {
                        'value': '10000'
                    },
                    'firewall_setting_engine_option_connections_num_udp_max': {
                        'value': '1000000'
                    },
                    'firewall_setting_engine_option_debug_mode_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_debug_packet_num_max': {
                        'value': '8'
                    },
                    'firewall_setting_engine_option_disconnect_timeout': {
                        'value': '60 '
                        'Seconds'
                    },
                    'firewall_setting_engine_option_drop6_to4_bogons_addresses_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_drop_evasive_retransmit_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_drop_ip_zero_payload_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_drop_ipv6_bogons_addresses_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_drop_ipv6_ext_type0_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_drop_ipv6_fragments_lower_than_min_mtu_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_drop_ipv6_reserved_addresses_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_drop_ipv6_site_local_addresses_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_drop_teredo_anomalies_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_drop_unknown_ssl_protocol_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_error_timeout': {
                        'value': '10 '
                        'Seconds'
                    },
                    'firewall_setting_engine_option_established_timeout': {
                        'value': '3 '
                        'Hours'
                    },
                    'firewall_setting_engine_option_event_nodes_max': {
                        'value': '20000'
                    },
                    'firewall_setting_engine_option_filter_ipv4_tunnels': {
                        'value': 'Disable '
                        'Detection '
                        'of '
                        'IPv4 '
                        'Tunnels'
                    },
                    'firewall_setting_engine_option_filter_ipv6_tunnels': {
                        'value': 'Disable '
                        'Detection '
                        'of '
                        'IPv6 '
                        'Tunnels'
                    },
                    'firewall_setting_engine_option_fin_wait1_timeout': {
                        'value': '2 '
                        'Minutes'
                    },
                    'firewall_setting_engine_option_force_allow_dhcp_dns': {
                        'value': 'Allow '
                        'DNS '
                        'Query '
                        'and '
                        'DHCP '
                        'Client'
                    },
                    'firewall_setting_engine_option_force_allow_icmp_type3_code4': {
                        'value': 'Add '
                        'Force '
                        'Allow '
                        'rule '
                        'for '
                        'ICMP '
                        'type3 '
                        'code4'
                    },
                    'firewall_setting_engine_option_fragment_offset_min': {
                        'value': '60'
                    },
                    'firewall_setting_engine_option_fragment_size_min': {
                        'value': '120'
                    },
                    'firewall_setting_engine_option_generate_connection_events_icmp_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_generate_connection_events_tcp_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_generate_connection_events_udp_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_icmp_timeout': {
                        'value': '60 '
                        'Seconds'
                    },
                    'firewall_setting_engine_option_ignore_status_code0': {
                        'value': 'None'
                    },
                    'firewall_setting_engine_option_ignore_status_code1': {
                        'value': 'None'
                    },
                    'firewall_setting_engine_option_ignore_status_code2': {
                        'value': 'None'
                    },
                    'firewall_setting_engine_option_last_ack_timeout': {
                        'value': '3 '
                        'Minutes'
                    },
                    'firewall_setting_engine_option_log_all_packet_data_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_log_events_per_second_max': {
                        'value': '100'
                    },
                    'firewall_setting_engine_option_log_one_packet_period': {
                        'value': '5 '
                        'Minutes'
                    },
                    'firewall_setting_engine_option_log_one_packet_within_period_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_log_packet_length_max': {
                        'value': '1500 '
                        'Bytes'
                    },
                    'firewall_setting_engine_option_logging_policy': {
                        'value': 'Default'
                    },
                    'firewall_setting_engine_option_silent_tcp_connection_drop_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_option_ssl_session_size': {
                        'value': 'Low '
                        '- '
                        '2500'
                    },
                    'firewall_setting_engine_option_ssl_session_time': {
                        'value': '24 '
                        'Hours'
                    },
                    'firewall_setting_engine_option_strict_terodo_port_check_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_engine_option_syn_rcvd_timeout': {
                        'value': '60 '
                        'Seconds'
                    },
                    'firewall_setting_engine_option_syn_sent_timeout': {
                        'value': '20 '
                        'Seconds'
                    },
                    'firewall_setting_engine_option_tcp_mss_limit': {
                        'value': 'No '
                        'Limit'
                    },
                    'firewall_setting_engine_option_tunnel_depth_max': {
                        'value': '1'
                    },
                    'firewall_setting_engine_option_tunnel_depth_max_exceeded_action': {
                        'value': 'Drop'
                    },
                    'firewall_setting_engine_option_udp_timeout': {
                        'value': '20 '
                        'Seconds'
                    },
                    'firewall_setting_engine_option_verify_tcp_checksum_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_engine_options_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_event_log_file_cached_entries_life_time': {
                        'value': '30 '
                        'Minutes'
                    },
                    'firewall_setting_event_log_file_cached_entries_num': {
                        'value': '128'
                    },
                    'firewall_setting_event_log_file_cached_entries_stale_time': {
                        'value': '15 '
                        'Minutes'
                    },
                    'firewall_setting_event_log_file_ignore_source_ip_list_id': {
                        'value': ''
                    },
                    'firewall_setting_event_log_file_retain_num': {
                        'value': '3'
                    },
                    'firewall_setting_event_log_file_size_max': {
                        'value': '4 '
                        'MB'
                    },
                    'firewall_setting_events_out_of_allowed_policy_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_failure_response_engine_system': {
                        'value': 'Fail '
                        'closed'
                    },
                    'firewall_setting_failure_response_packet_sanity_check': {
                        'value': 'Fail '
                        'closed'
                    },
                    'firewall_setting_interface_isolation_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_interface_limit_one_active_enabled': {
                        'value': 'false'
                    },
                    'firewall_setting_interface_patterns': {
                        'value': ''
                    },
                    'firewall_setting_network_engine_mode': {
                        'value': 'Inline'
                    },
                    'firewall_setting_reconnaissance_block_fingerprint_probe_duration': {
                        'value': 'No'
                    },
                    'firewall_setting_reconnaissance_block_network_or_port_scan_duration': {
                        'value': 'No'
                    },
                    'firewall_setting_reconnaissance_block_tcp_null_scan_duration': {
                        'value': 'No'
                    },
                    'firewall_setting_reconnaissance_block_tcp_syn_fin_scan_duration': {
                        'value': 'No'
                    },
                    'firewall_setting_reconnaissance_block_tcp_xmas_attack_duration': {
                        'value': 'No'
                    },
                    'firewall_setting_reconnaissance_detect_fingerprint_probe_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_detect_network_or_port_scan_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_detect_tcp_null_scan_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_detect_tcp_syn_fin_scan_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_detect_tcp_xmas_attack_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_exclude_ip_list_id': {
                        'value': '1'
                    },
                    'firewall_setting_reconnaissance_include_ip_list_id': {
                        'value': ''
                    },
                    'firewall_setting_reconnaissance_notify_fingerprint_probe_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_notify_network_or_port_scan_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_notify_tcp_null_scan_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_notify_tcp_syn_fin_scan_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_reconnaissance_notify_tcp_xmas_attack_enabled': {
                        'value': 'true'
                    },
                    'firewall_setting_virtual_and_container_network_scan_enabled': {
                        'value': 'false'
                    },
                    'integrity_monitoring_setting_auto_apply_recommendations_enabled': {
                        'value': 'No'
                    },
                    'integrity_monitoring_setting_combined_mode_protection_source': {
                        'value': 'Appliance '
                        'preferred'
                    },
                    'integrity_monitoring_setting_content_hash_algorithm': {
                        'value': 'sha1'
                    },
                    'integrity_monitoring_setting_cpu_usage_level': {
                        'value': 'High'
                    },
                    'integrity_monitoring_setting_realtime_enabled': {
                        'value': 'false'
                    },
                    'integrity_monitoring_setting_scan_cache_config_id': {
                        'value': '3'
                    },
                    'integrity_monitoring_setting_syslog_config_id': {
                        'value': '0'
                    },
                    'integrity_monitoring_setting_virtual_appliance_optimization_scan_cache_entries_max': {
                        'value': '500000'
                    },
                    'intrusion_prevention_setting_auto_apply_recommendations_enabled': {
                        'value': 'Yes'
                    },
                    'intrusion_prevention_setting_combined_mode_protection_source': {
                        'value': 'Agent '
                        'preferred'
                    },
                    'intrusion_prevention_setting_engine_option_fragmented_ip_keep_max': {
                        'value': '1000'
                    },
                    'intrusion_prevention_setting_engine_option_fragmented_ip_packet_send_icmp_enabled': {
                        'value': 'true'
                    },
                    'intrusion_prevention_setting_engine_option_fragmented_ip_timeout': {
                        'value': '60 '
                        'Seconds'
                    },
                    'intrusion_prevention_setting_engine_option_fragmented_ip_unconcerned_mac_address_bypass_enabled': {
                        'value': 'false'
                    },
                    'intrusion_prevention_setting_engine_options_enabled': {
                        'value': 'false'
                    },
                    'intrusion_prevention_setting_log_data_rule_first_match_enabled': {
                        'value': 'true'
                    },
                    'intrusion_prevention_setting_nsx_security_tagging_detect_mode_level': {
                        'value': 'No '
                        'Tagging'
                    },
                    'intrusion_prevention_setting_nsx_security_tagging_prevent_mode_level': {
                        'value': 'No '
                        'Tagging'
                    },
                    'intrusion_prevention_setting_virtual_and_container_network_scan_enabled': {
                        'value': 'true'
                    },
                    'log_inspection_setting_auto_apply_recommendations_enabled': {
                        'value': 'No'
                    },
                    'log_inspection_setting_severity_clipping_agent_event_send_syslog_level_min': {
                        'value': 'Medium '
                        '(6)'
                    },
                    'log_inspection_setting_severity_clipping_agent_event_store_level_min': {
                        'value': 'Medium '
                        '(6)'
                    },
                    'log_inspection_setting_syslog_config_id': {
                        'value': '0'
                    },
                    'platform_setting_agent_communications_direction': {
                        'value': 'Agent/Appliance '
                        'Initiated'
                    },
                    'platform_setting_agent_events_send_interval': {
                        'value': '60 '
                        'Seconds'
                    },
                    'platform_setting_agent_self_protection_enabled': {
                        'value': 'false'
                    },
                    'platform_setting_agent_self_protection_password': {
                        'value': ''
                    },
                    'platform_setting_agent_self_protection_password_enabled': {
                        'value': 'false'
                    },
                    'platform_setting_auto_assign_new_intrusion_prevention_rules_enabled': {
                        'value': 'true'
                    },
                    'platform_setting_auto_update_anti_malware_engine_enabled': {
                        'value': 'false'
                    },
                    'platform_setting_combined_mode_network_group_protection_source': {
                        'value': 'Agent '
                        'preferred'
                    },
                    'platform_setting_environment_variable_overrides': {
                        'value': ''
                    },
                    'platform_setting_heartbeat_inactive_vm_offline_alert_enabled': {
                        'value': 'false'
                    },
                    'platform_setting_heartbeat_interval': {
                        'value': '10 '
                        'Minutes'
                    },
                    'platform_setting_heartbeat_local_time_shift_alert_threshold': {
                        'value': 'Unlimited'
                    },
                    'platform_setting_heartbeat_missed_alert_threshold': {
                        'value': '5'
                    },
                    'platform_setting_inactive_agent_cleanup_override_enabled': {
                        'value': 'false'
                    },
                    'platform_setting_notifications_suppress_popups_enabled': {
                        'value': 'false'
                    },
                    'platform_setting_recommendation_ongoing_scans_interval': {
                        'value': '7 '
                        'Days'
                    },
                    'platform_setting_relay_state': {
                        'value': 'false'
                    },
                    'platform_setting_scan_cache_concurrency_max': {
                        'value': '1'
                    },
                    'platform_setting_scan_open_port_list_id': {
                        'value': '1-1024'
                    },
                    'platform_setting_smart_protection_anti_malware_global_server_proxy_id': {
                        'value': ''
                    },
                    'platform_setting_smart_protection_global_server_enabled': {
                        'value': 'true'
                    },
                    'platform_setting_smart_protection_global_server_proxy_id': {
                        'value': ''
                    },
                    'platform_setting_smart_protection_global_server_use_proxy_enabled': {
                        'value': 'false'
                    },
                    'platform_setting_troubleshooting_logging_level': {
                        'value': 'Do '
                        'Not '
                        'Override'
                    },
                    'platform_setting_upgrade_on_activation_enabled': {
                        'value': 'false'
                    },
                    'web_reputation_setting_alerting_enabled': {
                        'value': 'false'
                    },
                    'web_reputation_setting_allowed_url_domains': {
                        'value': ''
                    },
                    'web_reputation_setting_allowed_urls': {
                        'value': ''
                    },
                    'web_reputation_setting_blocked_url_domains': {
                        'value': ''
                    },
                    'web_reputation_setting_blocked_url_keywords': {
                        'value': ''
                    },
                    'web_reputation_setting_blocked_urls': {
                        'value': ''
                    },
                    'web_reputation_setting_blocking_page_link': {
                        'value': 'http://sitesafety.trendmicro.com/'
                    },
                    'web_reputation_setting_combined_mode_protection_source': {
                        'value': 'Agent '
                        'preferred'
                    },
                    'web_reputation_setting_monitor_port_list_id': {
                        'value': '80,8080'
                    },
                    'web_reputation_setting_security_block_untested_pages_enabled': {
                        'value': 'false'
                    },
                    'web_reputation_setting_security_level': {
                        'value': 'Medium'
                    },
                    'web_reputation_setting_smart_protection_global_server_use_proxy_enabled': {
                        'value': 'false'
                    },
                    'web_reputation_setting_smart_protection_local_server_allow_off_domain_global': {
                        'value': 'false'
                    },
                    'web_reputation_setting_smart_protection_local_server_enabled': {
                        'value': 'false'
                    },
                    'web_reputation_setting_smart_protection_local_server_urls': {
                        'value': ''
                    },
                    'web_reputation_setting_smart_protection_server_connection_lost_warning_enabled': {
                        'value': 'true'
                    },
                    'web_reputation_setting_smart_protection_web_reputation_global_server_proxy_id': {
                        'value': ''
                    },
                    'web_reputation_setting_syslog_config_id': {
                        'value': '0'
                    }
                },
                'recommendation_scan_mode': 'ongoing',
                'sap': None,
                'web_reputation': {
                    'module_status': {
                        'status': 'inactive',
                        'status_message': 'Off'
                    },
                    'state': 'off'
                }
            }


        """
        self.logger.entry("info", f'Searching for "{policy_name}" policy ID...')

        search_field = 'name'
        search_policies_api = api.PoliciesApi(self.api_client).search_policies
        result = self._find_exact_match(search_field, policy_name, search_policies_api)

        return result.policies[0]

    def create_policy(self, policy_name) -> int:
        """Creates a Deep Security policy

        Returns:
            int: Policy ID"""

        self.logger.entry('info', f'Policy name "{policy_name}" does not exist. Creating it...')

        # Create and configure a new policy
        new_policy = api.Policy()
        new_policy.name = policy_name
        new_policy.description = f'{policy_name} policy'
        new_policy.detection_engine_state = 'off'
        new_policy.auto_requires_update = 'on'

        # Create search criteria to retrieve the Base Policy
        search_criteria = api.SearchCriteria()
        search_criteria.field_name = 'name'
        search_criteria.string_test = 'equal'
        search_criteria.string_value = '%Base Policy%'
        search_criteria.max_results = 1

        # Create a search filter and pass the search criteria to it
        search_filter = api.SearchFilter(None, [search_criteria])

        try:
            # Search for the Base Policy
            policies_api = api.PoliciesApi(self.api_client)
            policy_search_results = policies_api.search_policies(self.api_version, search_filter=search_filter)

            # Set the parent ID of the new policy to the ID of the Base Policy
            new_policy.parent_id = policy_search_results.policies[0].id

            # Add the new policy to Deep Security Manager
            created_policy = policies_api.create_policy(new_policy, self.api_version)
            policy_id = created_policy.id

            self.logger.entry('info', f'Policy "{policy_name}" created successfully. Policy ID: {policy_id}')
            return policy_id

        except ApiException as e:
            self.logger.entry('critical', str(e))
            sys.exit(1)

    def add_ips_rules(self, policy_id, ips_rule_ids) -> None:
        """Adds IPS rule(s) to a policy"""
        ips_api = api.PolicyIntrusionPreventionRuleAssignmentsRecommendationsApi(self.api_client)
        ips_rule_api = api.RuleIDs()
        ips_rule_api.rule_ids = ips_rule_ids

        try:
            ips_api.add_intrusion_prevention_rule_ids_to_policy(
                policy_id,
                api_version=self.api_version,
                intrusion_prevention_rule_ids=ips_rule_api,
                overrides=False
            )

            self.logger.entry('info', 'Successfully applied new rule(s)')

        except ApiException as e:
            self.logger.entry('critical', str(e))
            sys.exit(1)

    def remove_ips_rules(self, policy_id, ips_rule_ids) -> None:
        """Removes IPS rule from a policy"""
        ips_api = api.PolicyIntrusionPreventionRuleAssignmentsRecommendationsApi(self.api_client)

        for ips_rule_id in ips_rule_ids:
            try:
                ips_api.remove_intrusion_prevention_rule_id_from_policy(
                    policy_id,
                    ips_rule_id,
                    api_version=self.api_version,
                    overrides=False
                )

                self.logger.entry('info', f'Successfully removed IPS rule ID {ips_rule_id}')

            except ApiException as e:
                self.logger.entry('critical', str(e))
                sys.exit(1)

    def set_computer_policy_id(self, computer_id, policy_id):
        """Moves computer to specified Policy"""
        computers_api = api.ComputersApi(self.api_client)
        computer = api.Computer()
        computer.policy_id = policy_id

        try:
            computers_api.modify_computer(computer_id, computer, self.api_version, overrides=False)

        except ApiException as e:
            self.logger.entry('critical', str(e))
            sys.exit(1)

    @staticmethod
    def _join_ints_as_str(int_list, sep=','):
        """Turns a list of integers into a CSV string"""
        joined_ips_rules = sep.join(str(rule_id) for rule_id in int_list)

        return joined_ips_rules

    def output_cve_ips_map(self, cve_ips_map, output_format='CSV'):
        output_format_upper = output_format.upper()

        msg = ['CVE to IPS rule map:\n']

        if output_format_upper == 'JSON':
            output = json.dumps(cve_ips_map)

        else:
            msg.append('CVE,IPS Rule ID\n')
            output = self._cve_ips_csv_format(cve_ips_map)

        msg.append(output)
        msg = ''.join(msg)

        self.logger.entry('info', msg, replace_newlines=False, replace_json=True)

    def _cve_ips_csv_format(self, cve_ips_map):
        output = []

        for cve, ips_rules in cve_ips_map.items():
            joined_rules = self._join_ints_as_str(ips_rules, sep=' ')
            entry = f'{cve},{joined_rules}'
            output.append(entry)

        joined_output = '\n'.join(output)

        return joined_output

    def json_response(self, status_code, msg) -> json:
        """Formats Lambda output

            Examples:
                Output::

                    {"statusCode": 200, "body": "\"No policy changes were required\""}

            Returns:
                json: Lambda output
        """

        output = {
            'statusCode': status_code,
            'body': json.dumps(msg)

        }

        json_output = json.dumps(output)
        self.logger.entry('info', f'Returning output:\n{json_output}')

        return json_output

    def str_to_bool(self, user_input, error_message):
        """Turns user input into a bool"""

        if user_input == 'true':
            enable_filters_bool = True

        elif user_input == 'false':
            enable_filters_bool = False

        else:
            self.logger.entry('critical', error_message)
            sys.exit(1)

        return enable_filters_bool
