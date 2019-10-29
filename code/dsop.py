import sys
import warnings
from libs.ds import Ds

if not sys.warnoptions:
    warnings.simplefilter('ignore')

APP_NAME = 'OpenPatch'


class Op(Ds):
    def __init__(self, hostname, policy_name, cve, console_logger=False, log_file_path='', print_logger=False,
                 log_level='INFO'):

        super().__init__(APP_NAME, console_logger, log_file_path, print_logger, log_level)

        self.hostname = hostname
        self.policy_name = policy_name
        self.cve = cve

        self.ips_rules = self.get_ips_rules()
        self.cve_ips_map = self.get_cve_ips_map(self.ips_rules)

    def run(self):
        self.logger.entry('info', f'Received {self.cve} and "{self.hostname}" for policy "{self.policy_name}"')
        policy_id, existing_ips_rule_ids = self.get_policy_rule_ids(self.policy_name)

        if not policy_id:
            policy_id = self.create_policy(self.policy_name)

        required_ips_rule_ids = self.cve_ips_map.get(self.cve)

        if not required_ips_rule_ids:
            msg = f'Cannot find an IPS rule for {self.cve}'
            self.logger.entry('critical', msg)
            status = self.json_response(400, msg)

            return status

        joined_ips_rules = self._join_ints_as_str(required_ips_rule_ids)
        self.logger.entry('info', f'{self.cve} maps to IPS rule(s): {joined_ips_rules}')
        self.logger.entry('info', f'Checking if rule(s) already applied to the "{self.policy_name}" policy...')

        if existing_ips_rule_ids:
            new_ips_rules_ids = list(set(required_ips_rule_ids) - set(existing_ips_rule_ids))

        else:
            new_ips_rules_ids = required_ips_rule_ids

        if new_ips_rules_ids:
            new_ips_rules_joined = self._join_ints_as_str(new_ips_rules_ids)
            self.logger.entry('info', f'Rules which need to be applied: {new_ips_rules_joined}')
            self.add_ips_rules(policy_id, required_ips_rule_ids)

        else:
            self.logger.entry('info', 'All required IPS rules are already applied. No policy modifications are '
                                      'required')

        self.logger.entry('info', f'Now checking if "{self.hostname}" is covered by policy "{self.policy_name}"')
        computer_id, computer_policy_id = self.get_computer(self.hostname)

        if computer_policy_id == policy_id:
            self.logger.entry('info', f'"{self.hostname}" is already covered by policy "{self.policy_name}". No '
                                      f'computer modifications are required')

        else:
            self.logger.entry('info', f'"{self.hostname}" Policy ID ({computer_policy_id}) does not match '
                                      f'"{self.policy_name}" Policy ID ({policy_id})')

            self.set_computer_policy_id(computer_id,  policy_id)
            self.logger.entry('info', f'Successfully moved "{self.hostname}" to Policy "{self.policy_name}"')

        self.logger.entry('info', f'Finished')

        status = self.json_response(200, 'OK')

        return status


def lambda_handler(event, context):
    hostname = event['hostname']
    policy_name = event['policy_name']
    cve = event['cve']

    op = Op(hostname, policy_name, cve, print_logger=True)
    status = op.run()

    return status
