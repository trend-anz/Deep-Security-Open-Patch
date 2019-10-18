import sys
import warnings
from libs.ds import Ds
from pprint import pprint

if not sys.warnoptions:
    warnings.simplefilter('ignore')

APP_NAME = 'OpenPatch'


class Op(Ds):
    def __init__(self, hostname, policy_name, cve, log_level='INFO'):
        super().__init__(APP_NAME, log_level)

        self.hostname = hostname
        self.policy_name = policy_name
        self.cve = cve

        self.logger.entry('info', f'Received {self.cve} and "{self.hostname}" for policy "{self.policy_name}"')

        self.ips_rules = self.get_ips_rules()
        self.cve_ips_map = self.get_cve_ips_map(self.ips_rules)

        self.run()

    def run(self):
        policy_id, existing_ips_rule_ids = self.get_policy_rule_ids(self.policy_name)

        if not policy_id:
            policy_id = self.create_policy(self.policy_name)

        required_ips_rule_ids = self.cve_ips_map.get(self.cve)

        if not required_ips_rule_ids:
            self.logger.entry('critical', f'Cannot find an IPS rule for {self.cve}')
            sys.exit(1)

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


Op('WIN-Q0HITV3HJ6D', 'Demo Policy', 'CVE-2017-0148')