import sys
import warnings
from libs.ds import Ds

if not sys.warnoptions:
    warnings.simplefilter('ignore')

APP_NAME = 'DsOpenPatch'


class Op(Ds):
    def __init__(self, app_name, console_logger=False, print_logger=False, log_level='INFO', log_file_path=''):
        super().__init__(app_name, console_logger, print_logger, log_level, log_file_path)

        self.ips_rules = self.get_ips_rules()
        self.cve_ips_map = self.get_cve_ips_map(self.ips_rules)

    def enable_ips_rules(self, hostname, computer_id, current_computer_policy_id, policy_id, policy_name,
                         existing_ips_rule_ids, cve_ips_rule_ids):
        changed = False

        if existing_ips_rule_ids:
            self.logger.entry('info', f'Checking if rule(s) already applied to the "{policy_name}" policy...')
            new_ips_rules_ids = list(set(cve_ips_rule_ids) - set(existing_ips_rule_ids))

        else:
            new_ips_rules_ids = cve_ips_rule_ids

        if new_ips_rules_ids:
            new_ips_rules_joined = self._join_ints_as_str(new_ips_rules_ids)
            self.logger.entry('info', f'Rules which need to be applied: {new_ips_rules_joined}')
            self.add_ips_rules(policy_id, cve_ips_rule_ids)
            changed = True

        else:
            self.logger.entry('info', 'All required IPS rules are already applied. No policy modifications are '
                                      'required')

        if current_computer_policy_id == policy_id:
            self.logger.entry('info', f'"{hostname}" is already covered by policy "{policy_name}". No computer '
                                      f'modifications are required')

        else:
            self.logger.entry('info', f'"{hostname}" Policy ID ({current_computer_policy_id}) does not match '
                                      f'"{policy_name}" Policy ID ({policy_id})')

            self.set_computer_policy_id(computer_id,  policy_id)
            self.logger.entry('info', f'Successfully moved "{hostname}" to Policy "{policy_name}"')
            changed = True

        if changed:
            msg = 'Policy changes were completed successfully'
        else:
            msg = 'No policy changes were required'

        self.logger.entry('info', msg)
        status = self.json_response(200, msg)

        return status

    def disable_ips_rules(self, policy_id, existing_ips_rule_ids, cve_ips_rule_ids):
        rules_to_remove = set(existing_ips_rule_ids).intersection(set(cve_ips_rule_ids))

        if rules_to_remove:
            self.remove_ips_rules(policy_id, cve_ips_rule_ids)
            msg = 'Successfully removed all relevant IPS rules'
            self.logger.entry('info', msg)
            status = self.json_response(200, msg)

        else:
            msg = 'Rules are not applied to policy. No changes need to be made'
            self.logger.entry('info', msg)
            status = self.json_response(200, msg)

        return status

    def get_computer_and_policy_ids(self, hostname):
        self.logger.entry("info", f"Obtaining {hostname}'s computer ID & current policy ID")

        try:
            computer_details = self.get_computer(hostname)

        except ValueError as e:
            msg = str(e)
            self.logger.entry('critical', msg)
            sys.exit(msg)

        computer_id = computer_details.id
        current_computer_policy_id = computer_details.policy_id
        self.logger.entry("info", f"Computer ID: {computer_id}, Policy ID: {current_computer_policy_id}")

        return computer_id, current_computer_policy_id

    def run(self, hostname, policy_name, cve, enable_rules=True):
        self.logger.entry('info', f'Received the following inputs: {cve} and "{hostname}" for policy "{policy_name}"')
        computer_id, current_computer_policy_id = self.get_computer_and_policy_ids(hostname)

        self.logger.entry('info', f'Checking if IPS rule(s) exist for {cve}')
        cve_ips_rule_ids = self.cve_ips_map.get(cve)

        if not cve_ips_rule_ids:
            msg = f'Cannot find IPS rule(s) for {cve}'
            self.logger.entry('critical', msg)
            status = self.json_response(400, msg)

            return status

        self.logger.entry('info', f'IPS rule(s) do exist for {cve}')

        try:
            self.logger.entry('info', f'Checking if "{policy_name}" exists')
            policy = self.get_policy(policy_name)
            self.logger.entry('info', f'"{policy_name}" does exists')
            policy_id = policy.id
            existing_ips_rule_ids = policy.intrusion_prevention.rule_ids
            existing_ips_rule_ids_str = self._join_ints_as_str(existing_ips_rule_ids)
            self.logger.entry('info', f'"{policy_name}" has the following rules applied: {existing_ips_rule_ids_str}')

        except IndexError:
            policy_id = self.create_policy(policy_name)
            existing_ips_rule_ids = None

        joined_ips_rules = self._join_ints_as_str(cve_ips_rule_ids)
        self.logger.entry('info', f'{cve} maps to IPS rule(s): {joined_ips_rules}')

        error_message = '"enable_rules" must be set to true or false'
        enable_rules_bool = self.str_to_bool(enable_rules, error_message)

        if enable_rules_bool:
            status = self.enable_ips_rules(hostname, computer_id, current_computer_policy_id, policy_id, policy_name,
                                           existing_ips_rule_ids, cve_ips_rule_ids)

        else:
            status = self.disable_ips_rules(policy_id, existing_ips_rule_ids, cve_ips_rule_ids)

        self.logger.entry('info', f'Finished')

        return status


def lambda_handler(event, context):
    hostname = event.get('hostname')
    policy_name = event['policy_name']
    cve = event['cve'].upper()
    enable_rules = event.get('enable_rules', 'true').lower()
    log_level = event.get('log_level', 'INFO').upper()

    op = Op(APP_NAME, print_logger=True, log_level=log_level)
    status = op.run(hostname, policy_name, cve, enable_rules)

    return status
