from proxmoxer import ProxmoxAPI
import time


def getproxmoxclient(node):
    """Create a ProxmoxAPI client from node config."""
    host = node.get('proxmoxhost', '')
    if not host:
        raise ValueError("No Proxmox host configured")
    
    # Remove protocol if present
    host = host.replace('https://', '').replace('http://', '').rstrip('/')
    
    return ProxmoxAPI(
        host,
        user=node.get('proxmoxuser', 'root@pam'),
        password=node.get('proxmoxpassword', ''),
        verify_ssl=bool(node.get('proxmoxssl', 0)),
        port=int(node.get('proxmoxport', 8006))
    )


def createlxc(pve, node_name, vmid, params):
    """Create LXC container."""
    return pve.nodes(node_name).lxc.create(vmid=vmid, **params)


def startlxc(pve, node_name, vmid):
    return pve.nodes(node_name).lxc(vmid).status.start.post()


def stoplxc(pve, node_name, vmid):
    return pve.nodes(node_name).lxc(vmid).status.stop.post()


def shutdownlxc(pve, node_name, vmid):
    return pve.nodes(node_name).lxc(vmid).status.shutdown.post()


def restartlxc(pve, node_name, vmid):
    return pve.nodes(node_name).lxc(vmid).status.reboot.post()


def deletelxc(pve, node_name, vmid):
    stoplxc(pve, node_name, vmid)
    time.sleep(2)
    return pve.nodes(node_name).lxc(vmid).delete()


def getlxcstatus(pve, node_name, vmid):
    return pve.nodes(node_name).lxc(vmid).status.current.get()


def getlxcconfig(pve, node_name, vmid):
    return pve.nodes(node_name).lxc(vmid).config.get()


def listlxc(pve, node_name):
    return pve.nodes(node_name).lxc.get()


def resizelxc(pve, node_name, vmid, disk, size):
    return pve.nodes(node_name).lxc(vmid).resize.post(disk=disk, size=size)


def nextvmid(pve):
    return pve.cluster.nextid.get()


def liststorage(pve, node_name, content_type=None):
    params = {}
    if content_type:
        params['content'] = content_type
    return pve.nodes(node_name).storage.get(**params)


def listtemplates(pve, node_name, storage):
    return pve.nodes(node_name).storage(storage).content.get(vztmpl=1)
