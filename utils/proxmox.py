from proxmoxer import ProxmoxAPI
import time


def getproxmoxclient(node, timeout=10):
    """Create a ProxmoxAPI client from node config."""
    host = node.get('proxmoxhost', '')
    if not host:
        raise ValueError("No Proxmox host configured")
    
    # Remove protocol if present
    host = host.replace('https://', '').replace('http://', '').rstrip('/')
    
    try:
        return ProxmoxAPI(
            host,
            user=node.get('proxmoxuser', 'root@pam'),
            password=node.get('proxmoxpassword', ''),
            verify_ssl=bool(node.get('proxmoxssl', 0)),
            port=int(node.get('proxmoxport', 8006)),
            timeout=timeout,
        )
    except TypeError:
        return ProxmoxAPI(
            host,
            user=node.get('proxmoxuser', 'root@pam'),
            password=node.get('proxmoxpassword', ''),
            verify_ssl=bool(node.get('proxmoxssl', 0)),
            port=int(node.get('proxmoxport', 8006)),
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


def _lxc_gone_message(msg):
    msg = (msg or "").lower()
    return (
        "does not exist" in msg
        or "not found" in msg
        or "configuration file" in msg
        or "no such file" in msg
        or "no such container" in msg
    )


def _lxc_exists(pve, node_name, vmid):
    try:
        getlxcstatus(pve, node_name, vmid)
        return True
    except Exception as e:
        if _lxc_gone_message(str(e)):
            return False
        try:
            for ct in listlxc(pve, node_name) or []:
                if str(ct.get("vmid")) == str(vmid):
                    return True
            return False
        except Exception:
            raise e


def waitlxcstopped(pve, node_name, vmid, timeout=120):
    """Poll until LXC is stopped or gone. Returns True if stopped/gone."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            cur = getlxcstatus(pve, node_name, vmid) or {}
            st = (cur.get("status") or "").lower()
            if st == "stopped":
                return True
        except Exception as e:
            msg = str(e).lower()
            if "does not exist" in msg or "not found" in msg or "configuration file" in msg:
                return True
            # transient — keep waiting
        time.sleep(2)
    return False


def stoplxc_wait(pve, node_name, vmid, timeout=120):
    """Stop LXC and wait until fully stopped (or already stopped/gone)."""
    if not _lxc_exists(pve, node_name, vmid):
        return True
    try:
        cur = getlxcstatus(pve, node_name, vmid) or {}
        if (cur.get("status") or "").lower() == "stopped":
            return True
    except Exception:
        pass
    try:
        stoplxc(pve, node_name, vmid)
    except Exception as e:
        msg = str(e).lower()
        # already stopped is fine
        if "already" not in msg and "not running" not in msg:
            # still try wait — may be stopping
            pass
    return waitlxcstopped(pve, node_name, vmid, timeout=timeout)


def _delete_lxc_api(pve, node_name, vmid):
    """Issue DELETE with best-supported params for this proxmoxer version."""
    endpoint = pve.nodes(node_name).lxc(vmid)
    # Proxmox API: DELETE /nodes/{node}/lxc/{vmid}?purge=1&force=1
    for kwargs in (
        {"purge": 1, "force": 1},
        {"purge": 1},
        {},
    ):
        try:
            return endpoint.delete(**kwargs)
        except TypeError:
            continue
        except Exception as e:
            # param not accepted by server — try next; other errors bubble
            msg = str(e).lower()
            if "force" in msg or "purge" in msg or "parameter" in msg:
                continue
            raise
    return endpoint.delete()


def deletelxc(pve, node_name, vmid, timeout=180):
    """
    Stop (wait) then delete LXC. Retries — Proxmox often 500s while CT still locking.
    """
    if not _lxc_exists(pve, node_name, vmid):
        return True

    stoplxc_wait(pve, node_name, vmid, timeout=min(timeout, 120))
    time.sleep(1)

    last_err = None
    attempts = max(4, timeout // 20)
    for i in range(attempts):
        if not _lxc_exists(pve, node_name, vmid):
            return True
        try:
            _delete_lxc_api(pve, node_name, vmid)
            gone_deadline = time.time() + 45
            while time.time() < gone_deadline:
                if not _lxc_exists(pve, node_name, vmid):
                    return True
                time.sleep(2)
            # delete accepted but still listed — keep retrying
        except Exception as e:
            last_err = e
            msg = str(e).lower()
            if (
                "does not exist" in msg
                or "not found" in msg
                or "configuration file" in msg
            ):
                return True
            try:
                stoplxc_wait(pve, node_name, vmid, timeout=30)
            except Exception:
                pass
            time.sleep(3 + i * 2)

    if not _lxc_exists(pve, node_name, vmid):
        return True
    if last_err:
        raise last_err
    raise RuntimeError(f"Failed to delete LXC {vmid} on {node_name}")


def getlxcstatus(pve, node_name, vmid):
    return pve.nodes(node_name).lxc(vmid).status.current.get()


def getlxcstats(pve, node_name, vmid, with_rrd=False):
    """Live LXC stats. Default: status.current only (fast). Optional RRD for rates."""
    status = getlxcstatus(pve, node_name, vmid) or {}
    if with_rrd:
        try:
            rrd = pve.nodes(node_name).lxc(vmid).rrddata.get(timeframe='hour', cf='AVERAGE')
            latest = rrd[-1] if rrd else {}
            status = {
                **status,
                "netin": latest.get("netin", 0) or 0,
                "netout": latest.get("netout", 0) or 0,
            }
        except Exception:
            pass
    return status


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
