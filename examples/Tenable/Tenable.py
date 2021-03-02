from dsop import Op
import csv

APP_NAME = 'DsOpenPatch'
LOG_LEVEL = 'INFO'
REPORT_FILENAME = 'Tenable-scan-results.csv'


def get_vulns():
    with open(REPORT_FILENAME) as csv_file:
        all_vulns = []

        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            cve = row.get('CVE')

            if not cve:
                continue

            host = row['Host']

            vuln = {
                'cve': cve,
                'hostname': host,
                'enable_rules': 'true',
            }

            print(f'INFO - Hostname {host} is vulnerable to {cve}')

            all_vulns.append(vuln)

    return all_vulns


def main():
    all_vulns = get_vulns()
    op = Op(app_name=APP_NAME, print_logger=True, log_level=LOG_LEVEL)

    for entry in all_vulns:
        entry['policy_name'] = 'Struts Hosts'
        op.run(**entry)


if __name__ == '__main__':
    main()
