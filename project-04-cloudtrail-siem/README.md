# Project 04 - CloudTrail Log Analysis & SIEM Integration

**Engineer:** Andre Wesley
**Date:** June 2026
**AWS Services:** CloudTrail, CloudWatch, S3, SNS, Splunk
**Frameworks:** AWS Well-Architected Security Pillar, NIST SP 800-92
**Difficulty:** Advanced

---

## Objective

Configure AWS CloudTrail for comprehensive API logging, ship logs to Splunk for SIEM correlation, build CloudWatch alarms for critical security events, and create detection rules aligned with MITRE ATT&CK Cloud techniques.

---

## Architecture

```
AWS API Activity
      |
       [CloudTrail] --> [S3 Bucket (cloudtrail-logs)] --> [S3 Event Notification]
             |                                                      |
              [CloudWatch Logs]                               [Lambda] --> [Splunk HEC]
                    |
                     [CloudWatch Alarms] --> [SNS Topic] --> [Email/PagerDuty Alert]
                     ```

                     ---

                     ## CloudTrail Setup

                     ```bash
                     # Create multi-region trail with log file validation
                     aws cloudtrail create-trail \
                       --name prod-security-trail \
                         --s3-bucket-name prod-cloudtrail-logs-2026 \
                           --include-global-service-events \
                             --is-multi-region-trail \
                               --enable-log-file-validation \
                                 --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/SecurityEvents:* \
                                   --cloud-watch-logs-role-arn arn:aws:iam::123456789012:role/CloudTrail-CWLogs-Role

                                   aws cloudtrail start-logging --name prod-security-trail

                                   # Enable CloudTrail Insights (anomaly detection)
                                   aws cloudtrail put-insight-selectors \
                                     --trail-name prod-security-trail \
                                       --insight-selectors '[{"InsightType": "ApiCallRateInsight"},{"InsightType": "ApiErrorRateInsight"}]'
                                       ```

                                       ---

                                       ## CloudWatch Alarm Rules

                                       ### Alarm 1 - Unauthorized API Calls

                                       ```bash
                                       # Metric filter for unauthorized API calls
                                       aws logs put-metric-filter \
                                         --log-group-name CloudTrail/SecurityEvents \
                                           --filter-name UnauthorizedAPICalls \
                                             --filter-pattern '{($.errorCode="*UnauthorizedAccess*") || ($.errorCode="AccessDenied*")}' \
                                               --metric-transformations metricName=UnauthorizedAPICalls,metricNamespace=CloudTrailMetrics,metricValue=1

                                               aws cloudwatch put-metric-alarm \
                                                 --alarm-name UnauthorizedAPICalls \
                                                   --alarm-description "Alert on unauthorized API calls" \
                                                     --metric-name UnauthorizedAPICalls \
                                                       --namespace CloudTrailMetrics \
                                                         --statistic Sum --period 300 --threshold 5 \
                                                           --comparison-operator GreaterThanOrEqualToThreshold \
                                                             --evaluation-periods 1 \
                                                               --alarm-actions arn:aws:sns:us-east-1:123456789012:security-alerts
                                                               ```

                                                               ### Alarm 2 - Root Account Usage

                                                               ```bash
                                                               aws logs put-metric-filter \
                                                                 --log-group-name CloudTrail/SecurityEvents \
                                                                   --filter-name RootAccountUsage \
                                                                     --filter-pattern '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}' \
                                                                       --metric-transformations metricName=RootAccountUsage,metricNamespace=CloudTrailMetrics,metricValue=1

                                                                       aws cloudwatch put-metric-alarm \
                                                                         --alarm-name RootAccountUsage \
                                                                           --alarm-description "CRITICAL: Root account used" \
                                                                             --metric-name RootAccountUsage --namespace CloudTrailMetrics \
                                                                               --statistic Sum --period 60 --threshold 1 \
                                                                                 --comparison-operator GreaterThanOrEqualToThreshold \
                                                                                   --evaluation-periods 1 \
                                                                                     --alarm-actions arn:aws:sns:us-east-1:123456789012:security-alerts
                                                                                     ```

                                                                                     ### Alarm 3 - IAM Policy Changes

                                                                                     ```bash
                                                                                     aws logs put-metric-filter \
                                                                                       --log-group-name CloudTrail/SecurityEvents \
                                                                                         --filter-name IAMPolicyChanges \
                                                                                           --filter-pattern '{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy)}' \
                                                                                             --metric-transformations metricName=IAMPolicyChanges,metricNamespace=CloudTrailMetrics,metricValue=1
                                                                                             ```

                                                                                             ### Alarm 4 - Security Group Changes

                                                                                             ```bash
                                                                                             aws logs put-metric-filter \
                                                                                               --log-group-name CloudTrail/SecurityEvents \
                                                                                                 --filter-name SecurityGroupChanges \
                                                                                                   --filter-pattern '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}' \
                                                                                                     --metric-transformations metricName=SecurityGroupChanges,metricNamespace=CloudTrailMetrics,metricValue=1
                                                                                                     ```
                                                                                                     
                                                                                                     ---
                                                                                                     
                                                                                                     ## Splunk CloudTrail Detection Queries
                                                                                                     
                                                                                                     ```spl
                                                                                                     # Query 1: Detect console logins without MFA
                                                                                                     index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin
                                                                                                     | where additionalEventData.MFAUsed="No"
                                                                                                     | table _time, userIdentity.userName, sourceIPAddress, userAgent
                                                                                                     | sort -_time
                                                                                                     
                                                                                                     # Query 2: Detect S3 bucket policy changes
                                                                                                     index=aws sourcetype=aws:cloudtrail
                                                                                                       (eventName=PutBucketPolicy OR eventName=DeleteBucketPolicy OR eventName=PutBucketAcl)
                                                                                                       | table _time, userIdentity.arn, eventName, requestParameters.bucketName
                                                                                                       | sort -_time
                                                                                                       
                                                                                                       # Query 3: Detect IAM privilege escalation attempts
                                                                                                       index=aws sourcetype=aws:cloudtrail
                                                                                                         (eventName=AttachUserPolicy OR eventName=PutUserPolicy OR eventName=AddUserToGroup)
                                                                                                         | where requestParameters.policyArn="*AdministratorAccess*" OR requestParameters.groupName="*Admin*"
                                                                                                         | table _time, userIdentity.arn, eventName, requestParameters
                                                                                                         
                                                                                                         # Query 4: Detect high-volume S3 data exfiltration
                                                                                                         index=aws sourcetype=aws:cloudtrail eventName=GetObject
                                                                                                         | bucket _time span=5m
                                                                                                         | stats count by _time, userIdentity.arn, requestParameters.bucketName
                                                                                                         | where count > 500
                                                                                                         | sort -count
                                                                                                         ```
                                                                                                         
                                                                                                         ---
                                                                                                         
                                                                                                         ## Detection Coverage Matrix
                                                                                                         
                                                                                                         | MITRE Technique | Detection Method | Alert Threshold |
                                                                                                         |---|--
