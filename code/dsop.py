import sys
import warnings
from libs.ds import Ds

if not sys.warnoptions:
    warnings.simplefilter('ignore')

APP_NAME = 'DsOpenPatch'


class Op(Ds):
    def __init__(self, app_name, console_logger=False, log_file_path='', print_logger=False,
                 log_level='INFO'):

        super().__init__(app_name, console_logger, log_file_path, print_logger, log_level)

        self.ips_rules = self.get_ips_rules()
        self.cve_ips_map = self.get_cve_ips_map(self.ips_rules)

    def enable_rules(self, hostname, policy_id, policy_name, existing_ips_rule_ids, cve_ips_rule_ids):
        self.logger.entry('info', f'Checking if rule(s) already applied to the "{policy_name}" policy...')

        changed = False

        if existing_ips_rule_ids:
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

        self.logger.entry('info', f'Now checking if "{hostname}" is covered by policy "{policy_name}"')
        computer_details = self.get_computer(hostname)
        computer_id = computer_details.computers[0].id
        computer_policy_id = computer_details.computers[0].policy_id

        if computer_policy_id == policy_id:
            self.logger.entry('info', f'"{hostname}" is already covered by policy "{policy_name}". No computer '
                                      f'modifications are required')

        else:
            self.logger.entry('info', f'"{hostname}" Policy ID ({computer_policy_id}) does not match '
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

    def disable_rules(self, policy_id, existing_ips_rule_ids, cve_ips_rule_ids):
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

    def run(self, hostname, policy_name, cve, enable_rules=True):
        self.logger.entry('info', f'Received {cve} and "{hostname}" for policy "{policy_name}"')
        policy_id, existing_ips_rule_ids = self.get_policy_rule_ids(policy_name)

        if not policy_id:
            policy_id = self.create_policy(policy_name)

        cve_ips_rule_ids = self.cve_ips_map.get(cve)

        if not cve_ips_rule_ids:
            msg = f'Cannot find IPS rule(s) for {cve}'
            self.logger.entry('critical', msg)
            status = self.json_response(400, msg)

            return status

        joined_ips_rules = self._join_ints_as_str(cve_ips_rule_ids)
        self.logger.entry('info', f'{cve} maps to IPS rule(s): {joined_ips_rules}')

        enable_rules_bool = self.str_to_bool(enable_rules)
        if enable_rules_bool:
            status = self.enable_rules(hostname, policy_id, policy_name, existing_ips_rule_ids, cve_ips_rule_ids)

        else:
            status = self.disable_rules(policy_id, existing_ips_rule_ids, cve_ips_rule_ids)

        self.logger.entry('info', f'Finished')

        return status


def lambda_handler(event, context):
    hostname = event.get('hostname')
    policy_name = event['policy_name']
    cve = event['cve']
    enable_rules = event.get('enable_rules', 'true').lower()
    log_level = event.get('log_level', 'INFO')

    op = Op(APP_NAME, print_logger=True, log_level=log_level)
    status = op.run(hostname, policy_name, cve, enable_rules)

    return status


demo_event = {
    'hostname': 'WIN-Q0HITV3HJ6D',
    'policy_name': 'Demo Policy',
    'cve': 'CVE-2014-3568',
    'log_level': 'DEBUG',
}

lambda_handler(demo_event, '')
