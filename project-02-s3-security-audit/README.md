# Project 02 - S3 Bucket Security Audit & Remediation

**Engineer:** Andre Wesley
**Date:** June 2026
**Frameworks:** CIS AWS Benchmark v1.5, AWS Well-Architected Security Pillar
**Difficulty:** Intermediate

---

## Objective

Audit all S3 buckets in an AWS account for public access misconfigurations, missing encryption, disabled versioning, and absent logging. Remediate all findings and implement preventive controls using AWS Config and S3 Block Public Access settings.

---

## Audit Summary

| Check | Buckets Audited | Passed | Failed |
|---|---|---|---|
| Block Public Access (Account-Level) | 1 (account setting) | FAIL | 1 |
| Block Public Access (Bucket-Level) | 14 | 9 | 5 |
| Default Encryption Enabled | 14 | 11 | 3 |
| Versioning Enabled | 14 | 6 | 8 |
| Server Access Logging | 14 | 4 | 10 |
| Bucket Policy - Least Privilege | 14 | 8 | 6 |
| MFA Delete Enabled | 14 | 0 | 14 |

---

## Critical Findings

### Finding 1 - Public S3 Bucket Exposing Company Data (CRITICAL)

```bash
# Identify public buckets
aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n' | while read bucket; do
  acl=$(aws s3api get-bucket-acl --bucket "$bucket" \
      --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' \
          --output text)
            if [ -n "$acl" ]; then echo "PUBLIC BUCKET: $bucket"; fi
            done
            # Output:
            # PUBLIC BUCKET: acme-marketing-assets-dev
            # PUBLIC BUCKET: acme-temp-uploads-2025
            ```

            **Remediation:**
            ```bash
            # Block public access at account level
            aws s3control put-public-access-block \
              --account-id 123456789012 \
                --public-access-block-configuration \
                  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
                  ```

                  ---

                  ### Finding 2 - Unencrypted S3 Buckets (HIGH)

                  3 buckets had no default encryption configured - all data stored in plaintext.

                  ```bash
                  # Enable KMS encryption on unencrypted buckets
                  aws s3api put-bucket-encryption \
                    --bucket acme-backups-2025 \
                      --server-side-encryption-configuration '{
                          "Rules": [{"ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                                      "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/mrk-xxxxx"
                                          }, "BucketKeyEnabled": true}]
                                            }'
                                            ```

                                            ---

                                            ### Finding 3 - Overly Permissive Bucket Policy (HIGH)

                                            ```json
                                            // BEFORE - Wildcard principal (allows any AWS account)
                                            {
                                              "Effect": "Allow",
                                                "Principal": "*",
                                                  "Action": "s3:GetObject",
                                                    "Resource": "arn:aws:s3:::acme-reports-bucket/*"
                                                    }

                                                    // AFTER - Restricted to specific role ARN
                                                    {
                                                      "Effect": "Allow",
                                                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/ReportsReaderRole"},
                                                          "Action": "s3:GetObject",
                                                            "Resource": "arn:aws:s3:::acme-reports-bucket/*"
                                                            }
                                                            ```

                                                            ---

                                                            ## Preventive Controls Implemented

                                                            ```bash
                                                            # Enable AWS Config rules for S3
                                                            aws configservice put-config-rule --config-rule '{"ConfigRuleName":"s3-bucket-public-read-prohibited","Source":{"Owner":"AWS","SourceIdentifier":"S3_BUCKET_PUBLIC_READ_PROHIBITED"}}'
                                                            aws configservice put-config-rule --config-rule '{"ConfigRuleName":"s3-bucket-server-side-encryption-enabled","Source":{"Owner":"AWS","SourceIdentifier":"S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"}}'
                                                            aws configservice put-config-rule --config-rule '{"ConfigRuleName":"s3-bucket-logging-enabled","Source":{"Owner":"AWS","SourceIdentifier":"S3_BUCKET_LOGGING_ENABLED"}}'
                                                            ```

                                                            ---

                                                            ## Post-Remediation Status

                                                            | Check | Status |
                                                            |---|---|
                                                            | Block Public Access (Account-Level) | PASS |
                                                            | All bucket public access blocked | 14/14 |
                                                            | Default encryption (KMS) | 14/14 |
                                                            | Versioning enabled | 14/14 |
                                                            | Server access logging | 14/14 |
                                                            | AWS Config rules active | 3 rules enforcing |
                                                            | Amazon Macie enabled | Scanning for sensitive data |

                                                            ---

                                                            ## Key Takeaways

                                                            - Enable S3 Block Public Access at the account level FIRST - eliminates public exposure risk across all buckets instantly
                                                            - Always use KMS-managed keys over AES-256 for regulated data - KMS provides key rotation and audit trails
                                                            - AWS Config provides continuous compliance - without it, misconfigurations persist for months undetected
                                                            - Amazon Macie identifies PII and regulated data automatically - essential for HIPAA/PCI-DSS environments

                                                            ---

                                                            ## References

                                                            - [CIS AWS S3 Controls](https://www.cisecurity.org/benchmark/amazon_web_services)
                                                            - [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
                                                            - [Amazon Macie Documentation](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
