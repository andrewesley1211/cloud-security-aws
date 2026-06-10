# Project 03 - Secure VPC Architecture with Multi-Tier Defense

**Engineer:** Andre Wesley
**Date:** June 2026
**Frameworks:** AWS Well-Architected Security Pillar, CIS AWS Benchmark v1.5
**Difficulty:** Advanced

---

## Objective

Design and implement a secure multi-tier VPC architecture for a production web application following the principle of defense-in-depth. Apply layered security controls at every tier: internet edge, application layer, database layer, and management plane.

---

## Architecture Overview

```
Internet
    |
    [AWS WAF + Shield]
        |
        [Internet Gateway]
            |
             +--[Public Subnet]--+
              | Application Load  |
               | Balancer (ALB)    |
                +-------------------+
                    |
                     +--[Private Subnet - App Tier]--+
                      | EC2 Auto Scaling Group        |
                       | (No direct internet access)   |
                        +-------------------------------+
                            |
                             +--[Private Subnet - DB Tier]---+
                              | RDS Multi-AZ (PostgreSQL)     |
                               | (No internet access)          |
                                +-------------------------------+
                                    |
                                     +--[Management Subnet]----------+
                                      | Bastion Host (SSM preferred)  |
                                       | VPC Flow Logs -> S3/CW Logs   |
                                        +-------------------------------+
                                        ```

                                        ---

                                        ## Security Group Rules

                                        ### ALB Security Group (sg-alb)

                                        | Direction | Protocol | Port | Source | Reason |
                                        |---|---|---|---|---|
                                        | Inbound | HTTPS | 443 | 0.0.0.0/0 | Public HTTPS traffic |
                                        | Inbound | HTTP | 80 | 0.0.0.0/0 | Redirect to HTTPS only |
                                        | Outbound | TCP | 8080 | sg-app | Forward to app tier |

                                        ### App Tier Security Group (sg-app)

                                        | Direction | Protocol | Port | Source | Reason |
                                        |---|---|---|---|---|
                                        | Inbound | TCP | 8080 | sg-alb | Only from ALB |
                                        | Inbound | TCP | 22 | sg-bastion | SSH from bastion only |
                                        | Outbound | TCP | 5432 | sg-db | PostgreSQL to DB tier |
                                        | Outbound | HTTPS | 443 | 0.0.0.0/0 | AWS API calls via NAT |

                                        ### DB Tier Security Group (sg-db)

                                        | Direction | Protocol | Port | Source | Reason |
                                        |---|---|---|---|---|
                                        | Inbound | TCP | 5432 | sg-app | Only from app tier |
                                        | Outbound | NONE | - | - | No outbound allowed |

                                        ### Bastion Security Group (sg-bastion)

                                        | Direction | Protocol | Port | Source | Reason |
                                        |---|---|---|---|---|
                                        | Inbound | TCP | 22 | Corporate IP CIDR | Strict IP whitelist |
                                        | Outbound | TCP | 22 | sg-app | SSH to app tier only |

                                        ---

                                        ## Network ACL Configuration

                                        ### Public Subnet NACL

                                        | Rule # | Direction | Protocol | Port | Action |
                                        |---|---|---|---|---|
                                        | 100 | Inbound | TCP | 443 | ALLOW |
                                        | 110 | Inbound | TCP | 80 | ALLOW |
                                        | 120 | Inbound | TCP | 1024-65535 | ALLOW (ephemeral) |
                                        | 200 | Outbound | TCP | 8080 | ALLOW |
                                        | 210 | Outbound | TCP | 1024-65535 | ALLOW (ephemeral) |
                                        | 32767 | Both | ALL | ALL | DENY |

                                        ---

                                        ## AWS WAF Rules Applied

                                        ```
                                        Rule 1: AWSManagedRulesCommonRuleSet       - OWASP Top 10 protection
                                        Rule 2: AWSManagedRulesKnownBadInputsRuleSet - Log4j, SSRF protection
                                        Rule 3: AWSManagedRulesSQLiRuleSet         - SQL injection prevention
                                        Rule 4: Rate limit rule                    - 2000 req/5min per IP
                                        Rule 5: Geo-blocking rule                  - Block high-risk countries
                                        ```

                                        ---

                                        ## Additional Security Controls

                                        - VPC Flow Logs enabled -> S3 (90-day retention) + CloudWatch Logs
                                        - GuardDuty enabled for threat detection across all VPC traffic
                                        - AWS Config rules: vpc-flow-logs-enabled, restricted-ssh, restricted-rdp
                                        - NAT Gateway for outbound-only internet access from private subnets
                                        - VPC Endpoints for S3, DynamoDB, SSM (avoid internet traversal)
                                        - AWS Systems Manager Session Manager preferred over Bastion SSH

                                        ---

                                        ## Key Takeaways

                                        - Security groups are stateful and applied at instance level; NACLs are stateless and applied at subnet level - use both for defense in depth
                                        - VPC Endpoints eliminate the need for NAT Gateway for AWS service calls, reducing attack surface and cost
                                        - SSM Session Manager eliminates the need for a bastion host and inbound SSH entirely - no open port 22
                                        - WAF Rate limiting is the first and fastest mitigation against automated attacks and DDoS

                                        ---

                                        ## References

                                        - [AWS VPC Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html)
                                        - [AWS WAF Documentation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)
                                        - [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
