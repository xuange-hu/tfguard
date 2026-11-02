"""The rule registry.

Every rule states two things a visitor can act on without reading the source:
**why** it is a problem, and **fix** — the change to make, not the concept.

The ids are grouped by the kind of mistake, not by the resource type, because
the question a reader has is "what did I get wrong", not "which AWS service is
this". Groups:

* 001-006 network exposure
* 010-017 encryption at rest
* 020-023 logging
* 030-034 identity
* 040-044 credentials in the graph
* 050-052 absent is not the same as empty
* 060-064 state and supply chain
* 070-075 relationships between blocks
"""

from __future__ import annotations

from tfguard.model import Rule

CATEGORY_LABELS = {
    "network": "network exposure",
    "encryption": "encryption at rest",
    "logging": "logging and forensics",
    "identity": "identity and access",
    "secrets": "credential handling",
    "absent": "absent vs empty",
    "supply": "state and supply chain",
    "relationship": "cross-block relationships",
}

RULES: list[Rule] = [
    # ---------------------------------------------------------------- network
    Rule(
        "TFG001",
        "Security group opens a remote-admin port to the internet",
        "critical",
        "network",
        'An ingress rule reachable from 0.0.0.0/0 on port 22 or 3389 puts SSH or RDP on the internet. '
        "It is the single most scanned-for configuration on the public cloud.",
        'Replace the CIDR with the address range that actually needs it, or drop the rule and reach the '
        "host through a bastion or SSM Session Manager.",
    ),
    Rule(
        "TFG002",
        "Security group opens a port to the internet",
        "high",
        "network",
        "An ingress rule from 0.0.0.0/0 exposes the port to every host on the internet, including "
        "services that were only meant to be internal.",
        "Scope the CIDR to the networks that need access, or front the service with a load balancer.",
    ),
    Rule(
        "TFG003",
        "Egress is unrestricted",
        "low",
        "network",
        "Egress to 0.0.0.0/0 lets anything that lands on the host talk to anything, which is what "
        "turns a small compromise into data leaving the account.",
        "Restrict egress to the destinations the workload needs, or route it through a NAT gateway.",
    ),
    Rule(
        "TFG004",
        "Database is publicly accessible",
        "high",
        "network",
        "publicly_accessible = true gives the instance a public IP, so the database answers on the "
        "internet even when the credentials are strong.",
        "Set publicly_accessible = false and reach it from inside the VPC.",
    ),
    Rule(
        "TFG005",
        "Instance takes a public IP",
        "medium",
        "network",
        "associate_public_ip_address = true puts the instance directly on the internet instead of "
        "behind a load balancer, which also removes the place you would put a WAF or an access log.",
        "Leave the instance private and publish it through a load balancer or a NAT for outbound only.",
    ),
    Rule(
        "TFG006",
        "Standalone security group rule opens an admin port to the internet",
        "high",
        "network",
        "aws_security_group_rule with a 0.0.0.0/0 CIDR on port 22 or 3389 is the same exposure as an "
        "inline rule, one block further from the resource it protects.",
        "Narrow the CIDR, or move the rule back into the security group so the attachment is visible.",
    ),
    # ------------------------------------------------------------- encryption
    Rule(
        "TFG010",
        "S3 bucket has no server-side encryption",
        "medium",
        "encryption",
        "Without a server_side_encryption_configuration block objects are stored unencrypted, and the "
        "bucket cannot satisfy an encryption requirement stated anywhere else in the account.",
        'Add a server_side_encryption_configuration block with sse_algorithm = "aws:kms".',
    ),
    Rule(
        "TFG011",
        "S3 bucket has a public ACL",
        "high",
        "encryption",
        "public-read or public-read-write on the ACL makes every object in the bucket readable by "
        "anyone, including objects added later.",
        'Remove the acl argument and grant access with a bucket policy tied to specific principals.',
    ),
    Rule(
        "TFG012",
        "EBS volume is not encrypted",
        "medium",
        "encryption",
        "An unencrypted volume has its data readable from a snapshot or from the underlying host, and "
        "the setting cannot be changed after creation without a copy.",
        "Set encrypted = true and give it a kms_key_id if the account has a customer-managed key.",
    ),
    Rule(
        "TFG013",
        "Database storage is not encrypted",
        "high",
        "encryption",
        "storage_encrypted is the only at-rest control on an RDS instance. It has to be set at creation "
        "time: turning it on later means a snapshot, an encrypted copy and a restore.",
        "Set storage_encrypted = true before the instance exists.",
    ),
    Rule(
        "TFG014",
        "S3 bucket has no versioning",
        "medium",
        "encryption",
        "Without versioning a delete or an overwrite is permanent. That is how both accidental loss and "
        "ransomware-style object replacement become unrecoverable.",
        'Add a versioning block with enabled = true.',
    ),
    Rule(
        "TFG015",
        "KMS key will not rotate",
        "medium",
        "encryption",
        "A key that never rotates keeps the same backing material forever, which widens the window every "
        "compromise of that material covers.",
        "Set enable_key_rotation = true.",
    ),
    Rule(
        "TFG017",
        "EFS file system is unencrypted",
        "medium",
        "encryption",
        "EFS encryption is enabled only when asked for. Like RDS it has to be decided at creation.",
        "Set encrypted = true.",
    ),
    # ---------------------------------------------------------------- logging
    Rule(
        "TFG020",
        "S3 bucket has no access logging",
        "low",
        "logging",
        "Without a logging block there is no record of who read what, which is the first question after "
        "any incident involving the bucket.",
        "Add a logging block pointing at a separate log-delivery bucket.",
    ),
    Rule(
        "TFG021",
        "Load balancer does not write access logs",
        "medium",
        "logging",
        "An internet-facing load balancer with no access_logs block sees every request and keeps none "
        "of them, so the traffic that matters most is the traffic you cannot review.",
        "Add an access_logs block with enabled = true and a target bucket.",
    ),
    Rule(
        "TFG022",
        "CloudTrail is weakened",
        "medium",
        "logging",
        "Log file validation off means a tampered log file is undetectable; a single-region trail means "
        "activity in the other regions was never recorded.",
        "Set enable_log_file_validation = true and is_multi_region_trail = true.",
    ),
    Rule(
        "TFG023",
        "VPC has no flow logs",
        "medium",
        "logging",
        "A VPC with no flow log attached records nothing about the connections crossing it, so there is "
        "no baseline to compare against during an incident.",
        "Attach an aws_flow_log to the VPC with a log destination and an IAM role that can write to it.",
    ),
    # ---------------------------------------------------------------- identity
    Rule(
        "TFG030",
        "Policy allows every action",
        "critical",
        "identity",
        'Action "*" with Effect "Allow" is administrative access by another name, whatever the resource '
        "attached to it was supposed to be for.",
        "List the actions the workload actually calls; start from CloudTrail if you do not know them.",
    ),
    Rule(
        "TFG031",
        "Policy applies to every resource",
        "high",
        "identity",
        'Resource "*" hands the granted actions over the whole account rather than the one thing the '
        "principal exists to touch.",
        "Point the policy at the specific ARNs, or at least at the account plus a resource path.",
    ),
    Rule(
        "TFG032",
        "Trust policy trusts everyone",
        "critical",
        "identity",
        'A Principal of "*" lets any principal in any account assume the role. It is the root of the '
        "confused-deputy class of cloud compromise.",
        "Name the accounts or services that may assume the role and add an external_id condition.",
    ),
    Rule(
        "TFG033",
        "Policy document combines a wildcard action with a wildcard resource",
        "high",
        "identity",
        "Neither wildcard alone is as dangerous as the pair: together they remove both the action limit "
        "and the scope limit in one statement.",
        "Constrain at least one side, and put the other behind a condition.",
    ),
    Rule(
        "TFG034",
        "Inline policy carries a wildcard",
        "high",
        "identity",
        "A policy attached directly to a role or user is invisible to account-wide policy review and "
        "travels with the principal when it is recreated.",
        "Move it to a managed aws_iam_policy and attach it, then narrow the wildcard.",
    ),
    # ---------------------------------------------------------------- secrets
    Rule(
        "TFG040",
        "A credential is written into the configuration",
        "critical",
        "secrets",
        "A literal password sitting in a resource argument is committed to the repository and printed "
        "in the plan output wherever the file is run.",
        "Move the value to a secrets manager and reference it as a data source.",
    ),
    Rule(
        "TFG041",
        "A credential is the default value of a variable",
        "critical",
        "secrets",
        "A default means anyone who runs terraform without overriding it gets the credential, and the "
        "file holding it is in version control.",
        "Drop the default, mark the variable sensitive, and pass the value from a secrets manager.",
    ),
    Rule(
        "TFG042",
        "A credential-shaped variable is not marked sensitive",
        "medium",
        "secrets",
        "Without sensitive = true the value is printed in plain text in plan and apply output, which "
        "ends up in CI logs and scrollback.",
        "Set sensitive = true on the variable.",
    ),
    Rule(
        "TFG043",
        "A credential reaches a plain argument through a variable",
        "high",
        "secrets",
        "The literal is not in this line, but the value still arrives here: it comes from a variable "
        "default, so it is committed to the repository all the same.",
        "Remove the default and supply the value from a secrets manager at apply time.",
    ),
    Rule(
        "TFG044",
        "A credential is rendered into user data or tags",
        "high",
        "secrets",
        "Values placed in user_data or tags are readable from the console, from instance metadata and "
        "from every backup of the instance.",
        "Fetch the secret at boot from a secrets manager instead of baking it into the template.",
    ),
    # ------------------------------------------------------------------ absent
    Rule(
        "TFG050",
        "Egress is closed by an empty list rather than by absence",
        "info",
        "absent",
        "egress = [] is a deliberate decision: you wrote it, and Terraform will not add the permissive "
        "default. This is recorded so the choice is visible, not as a defect.",
        "No change needed. Keep it; it is what makes the group safe to review.",
    ),
    Rule(
        "TFG051",
        "Tags are an empty map rather than absent",
        "info",
        "absent",
        "tags = {} says the resource was reviewed and deliberately carries no tags, which is different "
        "from nobody having looked.",
        "No change needed.",
    ),
    Rule(
        "TFG052",
        "Public access block exists but blocks nothing",
        "high",
        "absent",
        "All four flags off inside a public_access_block block looks like protection in a diff and "
        "behaves like nothing at all.",
        "Set block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets to true.",
    ),
    # ------------------------------------------------------------------ supply
    Rule(
        "TFG060",
        "State has no remote backend",
        "medium",
        "supply",
        "With no backend block the state file lives on one laptop, and it holds every resource id and "
        "every value that passed through the configuration.",
        "Add a backend block pointing at an encrypted, versioned bucket with a lock table.",
    ),
    Rule(
        "TFG061",
        "Remote state bucket is not encrypted or versioned",
        "medium",
        "supply",
        "The state file is the most sensitive artifact in the workspace. Unencrypted it is readable by "
        "anything that reaches the bucket; unversioned it has no history to recover from.",
        "Set encrypt = true in the backend block and enable versioning on the bucket.",
    ),
    Rule(
        "TFG062",
        "Provider version is not constrained",
        "medium",
        "supply",
        "With no version argument the next apply can pull a different provider, which is how a "
        "compromised release reaches a pipeline that never changed its own code.",
        "Give the provider a version constraint and commit the lock file.",
    ),
    Rule(
        "TFG063",
        "Module source is not pinned",
        "medium",
        "supply",
        "A module pulled from a branch or from a registry without a version can change under you without "
        "any commit in your repository to explain the change.",
        "Pin the ref for a git source or a version for a registry source.",
    ),
    Rule(
        "TFG064",
        "Terraform version is not constrained",
        "low",
        "supply",
        "required_version missing means the workspace will happily be applied by whatever terraform "
        "binary happens to be on the machine.",
        'Add required_version = ">= 1.5" to the terraform block.',
    ),
    # ------------------------------------------------------------- relationship
    Rule(
        "TFG070",
        "An internet-facing resource sits in a group that is open to the internet",
        "high",
        "relationship",
        "Neither block is wrong alone. Together they say the open group is the one protecting a resource "
        "that answers the internet, which is the exposure the two rules separately would not show.",
        "Attach a group that only admits the load balancer, and keep the open one off public workloads.",
    ),
    Rule(
        "TFG071",
        "A security group rule points at a group that is not defined here",
        "medium",
        "relationship",
        "The rule references a group this workspace does not declare, so what it actually protects "
        "depends on state somewhere else.",
        "Declare the group in this workspace, or take the id from a data source so the dependency is visible.",
    ),
    Rule(
        "TFG072",
        "Database relies on the default security group",
        "medium",
        "relationship",
        "With no vpc_security_group_ids the instance inherits the VPC default group, whose behaviour is "
        "not written down anywhere in this workspace.",
        "Give it a dedicated group whose ingress rules are in this file.",
    ),
    Rule(
        "TFG073",
        "Role trusts a policy document that trusts everyone",
        "high",
        "relationship",
        "The trust statement lives in the data block, so reading the role alone shows nothing. The pair "
        "is what grants the access.",
        "Replace Principal = \"*\" in the document with the accounts or services that may assume the role.",
    ),
    Rule(
        "TFG075",
        "A credential-shaped variable is published by an output",
        "high",
        "relationship",
        "An output prints its value at the end of every apply. If the variable it carries is a "
        "credential, the credential is now in the CI log.",
        "Set sensitive = true on the output, or do not publish the value at all.",
    ),
]

BY_ID: dict[str, Rule] = {r.id: r for r in RULES}


def get(rule_id: str) -> Rule | None:
    return BY_ID.get(rule_id.upper())


def by_category() -> dict[str, list[Rule]]:
    out: dict[str, list[Rule]] = {}
    for r in RULES:
        out.setdefault(r.category, []).append(r)
    return out


def ids() -> list[str]:
    return [r.id for r in RULES]
