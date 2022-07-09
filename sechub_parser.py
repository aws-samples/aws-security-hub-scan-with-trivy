# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json
import boto3
import datetime
import os

# import sechub + sts boto3 client
securityhub = boto3.client('securityhub')
sts = boto3.client('sts')

# retrieve account id from STS GetCallerID
getAccount = sts.get_caller_identity()
awsAccount = str(getAccount['Account'])
# retrieve env vars from codebuild
awsRegion = os.environ['AWS_REGION']
codebuildBuildArn = os.environ['CODEBUILD_BUILD_ARN']
containerName = os.environ['docker_img_name']
containerTag = os.environ['docker_tag']

# open Trivy vuln report & parse out vuln info
with open('results.json') as json_file:
    data = json.load(json_file)
Results = (list(data.keys())[4])
ResultValues = (data.get(Results))
if (ResultValues[0]['Vulnerabilities']) is None:
    print('No vulnerabilities')
else:
    for p in ResultValues[0]['Vulnerabilities']:
        cveId = str(p['VulnerabilityID'])
        cveTitle = str(p['Title'])
        cveDescription = str(p['Description'])
        cveDescription = (
            cveDescription[:1021] + '..') if len(cveDescription) > 1021 else cveDescription
        packageName = str(p['PkgName'])
        installedVersion = str(p['InstalledVersion'])
        fixedVersion = str(p['FixedVersion'])
        trivySeverity = str(p['Severity'])
        cveReference = str(p['References'][0])
        # create ISO 8601 timestamp
        iso8601Time = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc).isoformat()
        # map Trivy severity to ASFF severity
        if trivySeverity == 'LOW':
            trivyProductSev = int(1)
            trivyNormalizedSev = trivyProductSev * 10
        elif trivySeverity == 'MEDIUM':
            trivyProductSev = int(4)
            trivyNormalizedSev = trivyProductSev * 10
        elif trivySeverity == 'HIGH':
            trivyProductSev = int(7)
            trivyNormalizedSev = trivyProductSev * 10
        elif trivySeverity == 'CRITICAL':
            trivyProductSev = int(9)
            trivyNormalizedSev = trivyProductSev * 10
        else:
            print('No vulnerability information found')
        try:
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': containerName + ':' + containerTag + '/' + cveId,
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + ':product/aquasecurity/aquasecurity',
                        'GeneratorId': codebuildBuildArn,
                        'AwsAccountId': awsAccount,
                        'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': {
                            'Product': trivyProductSev,
                            'Normalized': trivyNormalizedSev
                        },
                        'Title': 'Trivy found a vulnerability to ' + cveId + ' in container ' + containerName,
                        'Description': cveDescription,
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'More information on this vulnerability is provided in the hyperlink',
                                'Url': cveReference
                            }
                        },
                        'ProductFields': {'Product Name': 'Trivy'},
                        'Resources': [
                            {
                                'Type': 'Container',
                                'Id': containerName + ':' + containerTag,
                                'Partition': 'aws',
                                'Region': awsRegion,
                                'Details': {
                                    'Container': {'ImageName': containerName + ':' + containerTag},
                                    'Other': {
                                        'CVE ID': cveId,
                                        'CVE Title': cveTitle,
                                        'Installed Package': packageName + ' ' + installedVersion,
                                        'Patched Package': packageName + ' ' + fixedVersion
                                    }
                                }
                            },
                        ],
                        'RecordState': 'ACTIVE'
                    }
                ]
            )
            print(response)
        except Exception as e:
            print(e)
            raise
