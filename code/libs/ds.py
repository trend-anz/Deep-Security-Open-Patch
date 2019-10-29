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
    def __init__(self, app_name, log_file_path=None, log_level='INFO'):
        self.app_name = app_name
        self.logger = Loggers(self.app_name, log_file_path, log_level)

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

    def get_app_types(self):
        self.logger.entry('info', 'Obtaining app types...')

        try:
            app_type_api = api.ApplicationTypesApi(self.api_client)
            app_list = app_type_api.list_application_types(self.api_version)

        except ApiException as e:
            return 'Exception: ' + str(e)

        app_types = dict()

        for app in app_list.application_types:
            app_types[app.id] = app

        num_app_types = len(app_types)
        self.logger.entry('info', f'Obtained {num_app_types} app types')
        self.logger.entry('debug', pformat(app_types))
        return app_types

    def get_computers(self):
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
            computers[computer.id] = computer

        num_computers = len(computers)
        self.logger.entry('info', f'Obtained {num_computers} computers')
        self.logger.entry('debug', pformat(computers))

        return computers

    def get_computer(self, hostname):
        self.logger.entry('info', f'Searching for "{hostname}" IDs...')

        search_field = 'hostName'
        search_computers_api = api.ComputersApi(self.api_client).search_computers
        computer = self._find_exact_match(search_field, hostname, search_computers_api)

        computer_id = computer.computers[0].id
        policy_id = computer.computers[0].policy_id

        self.logger.entry('info', f'"{hostname}" - Computer ID: {computer_id}, Policy ID: {policy_id}')
        return computer_id, policy_id

    def get_ips_rules(self):
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

    def get_cve_ips_map(self, ips_rules):
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

        return cve_map

    def _find_exact_match(self, search_field, search_string, object_api):
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

    def get_policy_rule_ids(self, policy_name):
        '''Get a list of rules applied to a policy'''
        self.logger.entry("info", f'Searching for "{policy_name}" policy ID...')

        search_field = 'name'
        search_policies_api = api.PoliciesApi(self.api_client).search_policies
        result = self._find_exact_match(search_field, policy_name, search_policies_api)

        if result.policies:
            policy_id = result.policies[0].id
            rule_ids = result.policies[0].intrusion_prevention.rule_ids

            if rule_ids and isinstance(rule_ids, list):
                joined_rule_ids = self._join_ints_as_str(rule_ids)

            else:
                joined_rule_ids = rule_ids

            self.logger.entry('info', f'Policy found - Policy ID: {policy_id}, Applied IPS rule IDs: {joined_rule_ids}')

            return policy_id, rule_ids

        else:
            return None, None

    def create_policy(self, policy_name):
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

    def add_ips_rules(self, policy_id, ips_rule_ids):
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

    def set_computer_policy_id(self, computer_id, policy_id):
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

    def json_response(self, status_code, msg):
        output = {
            'statusCode': status_code,
            'body': msg

        }

        json_output = json.dumps(output)
        self.logger.entry('info', f'Returning the output:\n{json_output}')

        return json_output
