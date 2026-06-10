# Project 01 - IAM Security Hardening & Least Privilege Audit

**Engineer:** Andre Wesley
**Date:** June 2026
**Certification Applied:** AWS Certified Cloud Practitioner
**Frameworks:** CIS AWS Benchmark v1.5, AWS Well-Architected Security Pillar
**Difficulty:** Intermediate

---

## Objective

Conduct a comprehensive IAM security audit on an AWS account, identify over-privileged users and roles, enforce least privilege, enable MFA, and establish a sustainable identity governance posture.

---

## Environment

| Component | Details |
|---|---|
| AWS Account | Sandbox/Lab environment |
| Region | us-east-1 |
| Users Audited | 12 IAM users |
| Roles Audited | 8 IAM roles |
| Policies Reviewed | 23 managed + 11 inline policies |

---

## Audit Findings

### Finding 1 - Root Account Has Active Access Keys (CRITICAL)

**CIS Control:** 1.4 - Ensure no root account access key exists

```bash
# Check via AWS CLI
aws iam get-account-summary | grep "AccountAccessKeysPresent"
# Output: "AccountAccessKeysPresent": 1  <- FAIL
```

**Remediation:** Delete root access keys via IAM Console -> Security Credentials -> Access Keys -> Delete

---

### Finding 2 - MFA Not Enabled for 7 of 12 IAM Users (HIGH)

**CIS Control:** 1.10 - Ensure MFA is enabled for all IAM users with console access

```bash
# Identify users without MFA
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F',' 'NR>1 && $8=="false" {print $1}'
# Output: dev-user1, dev-user2, contractor-bob, [4 more...]
```

**SCP Enforcement:** Applied DenyAllExceptMFA policy to block API calls without MFA token present.

---

### Finding 3 - Wildcard Permissions in Inline Policies (HIGH)

3 IAM users had inline policies containing `"Action": "*"` and `"Resource": "*"` granting administrator access without being in the Admins group.

```json
// BEFORE (insecure)
{ "Effect": "Allow", "Action": "*", "Resource": "*" }

// AFTER (least privilege)
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": ["arn:aws:s3:::company-dev-bucket", "arn:aws:s3:::company-dev-bucket/*"]
}
```

---

### Finding 4 - Unused Access Keys Older Than 90 Days (MEDIUM)

4 access keys identified as stale -> Deactivated and scheduled for deletion.

```bash
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F',' 'NR>1 {print $1, $11}' | awk '$2 < "2026-03-01" {print $1}'
```

---

### Finding 5 - CloudTrail Not Enabled in All Regions (MEDIUM)

```bash
aws cloudtrail create-trail \
  --name org-security-trail \
  --s3-bucket-name org-cloudtrail-logs-2026 \
  --is-multi-region-trail \
  --enable-log-file-validation
aws cloudtrail start-logging --name org-security-trail
```

---

## IAM Hardening Checklist

| Control | Before | After |
|---|---|---|
| Root access keys deleted | FAIL | PASS |
| Root account MFA enabled | FAIL | PASS |
| MFA for all console users | 42% compliant | 100% compliant |
| No wildcard policies | 3 violations | Remediated |
| Password policy enforced | Not set | Enforced |
| Unused access keys (90+ days) | 4 keys active | Deactivated |
| CloudTrail multi-region | Single region | All regions |
| Access Analyzer enabled | Disabled | Enabled |

---

## Key Takeaways

- Wildcard policies in inline policies are often overlooked during access reviews - always check inline policies, not just managed ones
- SCP-enforced MFA is more reliable than policy-based MFA because it applies organization-wide
- AWS IAM Access Analyzer should be the first tool enabled in any new AWS account
- Unused credentials are the #1 attack surface for credential-based cloud breaches

---

## References

- [CIS AWS Benchmark v1.5](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
