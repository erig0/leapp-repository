from leapp.models import FirewalldGlobalConfig

try:
    from firewall.core.fw import Firewall
except ImportError:
    pass


def read_config():
    try:
        fw = Firewall(offline=True)
    except NameError:
        # import failure missing means firewalld is not installed. Just return
        # the defaults.
        return FirewalldGlobalConfig()

    # This does not actually start firewalld. It just loads the configuration a
    # la firewall-offline-cmd.
    fw.start()

    conf = fw.config.get_firewalld_conf()

    return FirewalldGlobalConfig(FIXME)
