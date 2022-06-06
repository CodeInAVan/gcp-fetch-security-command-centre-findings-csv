# Fetch GCP Security Centre Findings

Small script (copy of https://github.com/dominikjaeckle/aws-fetch-security-hub-findings ) to fetch gcp security command centre findings based on defined account_ids and filters. The script reads a configuration file and fetches the security findings based on pre-defined account_ids and filters, which are to be defined in the settings_gcp.yaml file. 

The script expects gcp account credentials in a file gcpcreds.json (see example).

Modified to support a csv output and adapted for gcp gcloud from https://github.com/dominikjaeckle orginal aws script.

## Prerequisites
If you have not done so, setup gcloud cli and configure a service account similar to those required for cloudsploit or similar tools ( https://github.com/aquasecurity/cloudsploit/blob/master/docs/gcp.md)

Also install the requirements:
```bash
$ pip install -r requirements.txt
```

## Configuration
Find the configuration in the **settings_gcp.yaml** file.
```yaml
# Configure all accounts your credentials has access to.
accounts:
  - $$account_id1$$
  - $$account_di2$$
  - ...

# filters to be used to filter for security findints
filters:
  - filter_name: state
    value: ACTIVE
    comparison: '='

```
Create a **gcpcreds.json**, paste in your service account .json file.

## Fetch the Security Hub Findings
Run the following command to fetch the security hub findings
```bash
$ python3 gcp_fetch_sec_findings.py
```

In the same directory, the script will generate a file called **security_findings_%Y%m%d.html** and a file **security_findings_%Y%m%d.csv**, which can be opened in any browser. 

## Extensions
The basic set of attributes that is extracted from the security hub findings can be extended as per your convinience. So far, the following definition exists using pydantic:

```python
class Finding(BaseModel):
    environment: str = ''
    account_id: str = ''
    created_at: str = ''
    updated_at: str = ''
    compliance_status: str = ''
    title: str = ''
    description: str = ''
    recommendation_text: str = ''
    recommendation_url: str = ''
    workflow_state: str = ''
    workflow_status: str = ''
    record_state: str = ''
    severity_label: str = ''
```