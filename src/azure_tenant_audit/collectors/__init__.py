from .app_credentials import AppCredentialsCollector
from .identity import IdentityCollector
from .app_consent import AppConsentCollector
from .conditional_access import ConditionalAccessCollector
from .consent_policy import ConsentPolicyCollector
from .copilot_governance import CopilotGovernanceCollector
from .cross_tenant_access import CrossTenantAccessCollector
from .defender_cloud_apps import DefenderCloudAppsCollector
from .defender import DefenderCollector
from .dns_posture import DnsPostureCollector
from .domains_hybrid import DomainsHybridCollector
from .ediscovery import EDiscoveryCollector
from .exchange_policy import ExchangePolicyCollector
from .external_identity import ExternalIdentityCollector
from .identity_governance import IdentityGovernanceCollector
from .identity_protection import IdentityProtectionCollector
from .intune_depth import IntuneDepthCollector
from .licensing import LicensingCollector
from .mailbox_forwarding import MailboxForwardingCollector
from .onedrive_posture import OneDrivePostureCollector
from .power_platform import PowerPlatformCollector
from .purview import PurviewCollector
from .reports_usage import ReportsUsageCollector
from .security import SecurityCollector
from .sentinel_xdr import SentinelXdrCollector
from .service_health import ServiceHealthCollector
from .auth_methods import AuthMethodsCollector
from .intune import IntuneCollector
from .sharepoint import SharePointCollector
from .sharepoint_access import SharePointAccessCollector
from .teams import TeamsCollector
from .teams_policy import TeamsPolicyCollector
from .exchange import ExchangeCollector

REGISTRY = {
    "identity": IdentityCollector(),
    "app_consent": AppConsentCollector(),
    "app_credentials": AppCredentialsCollector(),
    "security": SecurityCollector(),
    "conditional_access": ConditionalAccessCollector(),
    "consent_policy": ConsentPolicyCollector(),
    "cross_tenant_access": CrossTenantAccessCollector(),
    "defender": DefenderCollector(),
    "dns_posture": DnsPostureCollector(),
    "domains_hybrid": DomainsHybridCollector(),
    "auth_methods": AuthMethodsCollector(),
    "external_identity": ExternalIdentityCollector(),
    "intune": IntuneCollector(),
    "intune_depth": IntuneDepthCollector(),
    "licensing": LicensingCollector(),
    "mailbox_forwarding": MailboxForwardingCollector(),
    "identity_governance": IdentityGovernanceCollector(),
    "onedrive_posture": OneDrivePostureCollector(),
    "power_platform": PowerPlatformCollector(),
    "sentinel_xdr": SentinelXdrCollector(),
    "identity_protection": IdentityProtectionCollector(),
    "defender_cloud_apps": DefenderCloudAppsCollector(),
    "copilot_governance": CopilotGovernanceCollector(),
    "sharepoint": SharePointCollector(),
    "sharepoint_access": SharePointAccessCollector(),
    "teams": TeamsCollector(),
    "teams_policy": TeamsPolicyCollector(),
    "reports_usage": ReportsUsageCollector(),
    "service_health": ServiceHealthCollector(),
    "exchange": ExchangeCollector(),
    "exchange_policy": ExchangePolicyCollector(),
    "purview": PurviewCollector(),
    "ediscovery": EDiscoveryCollector(),
}
