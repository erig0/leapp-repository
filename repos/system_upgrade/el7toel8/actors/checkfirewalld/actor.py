from leapp.actors import Actor
from leapp.models import FirewalldFacts
from leapp.reporting import Report
from leapp.libraries.common.reporting import report_with_remediation
from leapp.tags import ChecksPhaseTag, IPUWorkflowTag

from leapp.libraries.actor import private


class CheckFirewalld(Actor):
    """
    Checks for certain firewalld configuration that may prevent an upgrade.
    """

    name = 'check_firewalld'
    consumes = (FirewalldFacts,)
    produces = (Report,)
    tags = (ChecksPhaseTag, IPUWorkflowTag)

    def process(self):
        for facts in self.consume(FirewalldFacts):
            for table in facts.ebtablesTablesInUse:
                if not private.isEbtablesTableSupported(table):
                    report_with_remediation(
                        title='Firewalld is using an unsupported ebtables table.',
                        summary='ebtables in RHEL-8 does not support the {} table.'.format(table),
                        remediation='Remove firewalld direct rules that use ebtables {} table.'.format(table),
                        severity='high',
                        flags=['inhibitor'])
            for ipset_type in facts.ipsetTypesInUse:
                if not private.isIpsetTypeSupportedByNftables(ipset_type):
                    report_with_remediation(
                        title='Firewalld is using an unsupported ipset type.',
                        summary='ipset type \'{}\' is not supported by firewalld\'s nftables backend.'.format(ipset_type),
                        remediation='Remove ipsets of type {} from firewalld.'.format(ipset_type),
                        severity='high',
                        flags=['inhibitor'])
