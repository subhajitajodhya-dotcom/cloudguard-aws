"""Network rules (security groups and subnets)."""

from __future__ import annotations

from app.scanner.models import Finding
from app.scanner.registry import ScanContext, rule

# Ports that should never be open to the whole internet.
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}


def _open_to_world(permission: dict) -> bool:
    ipv4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in permission.get("IpRanges", []))
    ipv6 = any(r.get("CidrIpv6") == "::/0" for r in permission.get("Ipv6Ranges", []))
    return ipv4 or ipv6


def exposed_ports(permission: dict) -> list[int]:
    """Sensitive ports covered by one ingress rule. Empty list means none."""
    if permission.get("IpProtocol") == "-1":
        return list(SENSITIVE_PORTS)
    if permission.get("IpProtocol") not in ("tcp", "6"):
        return []
    low = permission.get("FromPort", 0)
    high = permission.get("ToPort", 65535)
    return [p for p in SENSITIVE_PORTS if low <= p <= high]


@rule("NET-001", "Security group does not expose sensitive ports to the internet")
def open_sensitive_ports(ctx: ScanContext) -> list[Finding]:
    findings = []
    for region in ctx.regions:
        ec2 = ctx.client("ec2", region)
        for group in ec2.describe_security_groups()["SecurityGroups"]:
            for perm in group.get("IpPermissions", []):
                if not _open_to_world(perm):
                    continue
                ports = exposed_ports(perm)
                if not ports:
                    continue
                all_traffic = perm.get("IpProtocol") == "-1"
                names = ", ".join(f"{SENSITIVE_PORTS[p]} ({p})" for p in ports[:4])
                findings.append(
                    Finding(
                        rule_id="NET-001",
                        title="Security group allows the internet to reach sensitive ports",
                        severity="CRITICAL" if all_traffic else "HIGH",
                        resource=f"{group['GroupId']} ({group.get('GroupName', '')})",
                        region=region,
                        description=(
                            "All traffic is open to 0.0.0.0/0."
                            if all_traffic
                            else f"Open to 0.0.0.0/0 or ::/0: {names}."
                        ),
                        remediation="Restrict the source to your own IP range or a VPN, or remove the rule.",
                    )
                )
    return findings


@rule("NET-002", "Subnet does not hand out public IPs by default")
def subnet_public_ip(ctx: ScanContext) -> list[Finding]:
    findings = []
    for region in ctx.regions:
        ec2 = ctx.client("ec2", region)
        for subnet in ec2.describe_subnets()["Subnets"]:
            if subnet.get("DefaultForAz"):
                continue  # default VPC subnets are public by design
            if subnet.get("MapPublicIpOnLaunch"):
                findings.append(
                    Finding(
                        rule_id="NET-002",
                        title="Subnet auto-assigns public IP addresses",
                        severity="LOW",
                        resource=subnet["SubnetId"],
                        region=region,
                        description="Every instance launched here gets a public IP unless told otherwise.",
                        remediation="Turn off auto-assign public IP, or keep it only on subnets meant to be public.",
                    )
                )
    return findings
