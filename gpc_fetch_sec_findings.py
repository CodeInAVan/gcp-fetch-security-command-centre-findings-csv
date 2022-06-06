import os
import json
import yaml
from datetime import datetime
from pydantic import BaseModel
from typing import List

class Finding(BaseModel):
    account_id: str = ''
    created_at: str = ''
    updated_at: str = ''
    compliance_status: str = ''
    category: str = ''
    description: str = ''
    recommendation_text: str = ''
    record_state: str = ''
    severity_label: str = ''
    resource_type: str = ''
    resource_id: str = ''
    resource_details: str = ''
    canonicalName: str = ''
    findingClass: str = ''


def fetch_findings(environment: str, filterstr: str, sortcriteria: str) -> List[Finding]:
    '''
        Fetches the findings from a given aws account following a certain filter and sorting criteria
    '''

    os.environ['GCP_ACCOUNT'] = environment
    os.environ['GCP_FILTER'] = filterstr
    #print(filterstr)

    cmdstring = 'gcloud scc findings list projects/$GCP_ACCOUNT --filter=\"$GCP_FILTER\"'
    #print(cmdstring)

    findings_raw = os.popen(cmdstring)
    #exit
    
    findings_yaml = yaml.safe_load_all(findings_raw.read())

    # for doc in findings_yaml:
    #     print(doc)

    findings: List[Finding] = []
    for f in findings_yaml:
        finding = Finding()
        finding.canonicalName = f["finding"]["canonicalName"]
        finding.account_id = f["resource"]["projectDisplayName"]
        finding.created_at = f["finding"]['createTime']
        finding.findingClass = f["finding"]['findingClass']
        finding.updated_at = f["finding"]['eventTime']
        finding.compliance_status = str(f["finding"]['compliances'])
        finding.category = f["finding"]["category"]
        finding.description = f["finding"]["description"]
        finding.recommendation_text = f["finding"]["sourceProperties"]["Recommendation"] if ("sourceProperties" in f["finding"].keys()) else ''
        finding.record_state = f["finding"]["state"]
        finding.severity_label = f["finding"]["severity"]
        finding.resource_type = str(f["resource"]["type"])
        finding.resource_id = f["resource"]["name"]
        finding.resource_details = str(f["resource"])
        print(finding)
        #exit()

        findings.append(finding)


    return findings

def create_valid_html(findings: List[Finding]):
    '''
        Creates a html report from the given findings
    '''

    file = open(f'security_findings_{datetime.now().strftime("%Y%m%d")}.html','w')
    file2 = open(f'security_findings_{datetime.now().strftime("%Y%m%d")}.csv','w')
    csv = ''
    html = '''
        <html>
        <head>
            <style>
                body, html {
                    font-family: Arial, sans-serif;
                    font-size: 0.9em;
                }
                table {
                    width: 100%;
                    font-size: 0.4em;
                }
                table tr th {
                    background-color: whitesmoke;
                }
                table, td, th {
                    border:1px solid black;
                    border-collapse: collapse;
                }
                td, th {
                    padding: 5px;
                }
            </style>
        </head>
        <body>
            <h1>Security Findings<h1>
            <table>
    '''

    if (len(findings) > 0):
        html += '<tr>'
        html += '<th>index</th>'
        csv += 'index,'
        for key, value in findings[0]:
            html += f'<th>{key}</th>'
            csv += f'{key},'
        html += '</tr>'
        csv += f'\n'

    index = 0
    for finding in findings:
        html += f'<tr style="background-color: {"#ffcfcc" if finding.severity_label == "HIGH" else "#F492B8" if finding.severity_label == "CRITICAL" else "none"}">'
        html += f'<td>{index}</td>'
        csv += f'{index},'
        for key, value in finding:
            html += f'<td>{value}</td>'
            csv += f'"{value.replace(","," ")}",'
        html += '</tr>'
        csv += f'\n'
        index += 1

    html += '</table></body></html>'

    file.write(html)
    file.close()
    file2.write(csv)
    file2.close()

if __name__ == '__main__':
    '''
        Fetches all security findings that follow a certain filter criteria.
        The script is executed on the locally configered AWS environments and requires that awssso was run before.

        https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html
    '''
    settings = None
    with open('settings_gcp.yaml', 'r') as stream:
        settings = yaml.safe_load(stream)

    # fetch environments and build filters and sorting criteria
    environments = settings['accounts']
    #print(environments)
    #filterstr = ''
    sortcriteria = ''
    filterstr = ''.join(f'{x["filter_name"]}{x["comparison"]}\"{x["value"]}\"' for x in settings['filters'])
   # sortcriteria = f'\'{{"Field": "{settings["sort_criteria"]["field"]}", "SortOrder": "{settings["sort_criteria"]["sort_order"]}"}}\''

    # fetch all findings and create a html report
    findings = [finding for env in environments for finding in fetch_findings(environment=env, filterstr=filterstr, sortcriteria=sortcriteria)]
    create_valid_html(findings=findings)

    print(f'Finished, Found: {len(findings)} finding(s)')
