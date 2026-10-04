import json
import os
import subprocess
import threading
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


class ActiveMitigationStatus:
    last_target = None
    last_action = None
    last_result = None
    last_error = None
    active = False


def _post_to_sdn_controller(controller_url, target_mac):
    payload = {
        "dpid": 1,
        "table_id": 0,
        "priority": 40000,
        "match": {"dl_src": target_mac},
        "actions": []
    }

    if requests is None:
        # Fallback to urllib if requests is missing
        try:
            import urllib.request
            import urllib.error
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                controller_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, resp.read().decode("utf-8")
        except Exception as err:
            raise RuntimeError(f"SDN POST failed: {err}")

    response = requests.post(controller_url, json=payload, timeout=15)
    response.raise_for_status()
    return response.status_code, response.text


def _run_ansible_playbook(target_mac, ovs_bridge, controller_url):
    playbook_path = Path("isolate_malicious_node.yml")
    if not playbook_path.exists():
        raise FileNotFoundError("isolate_malicious_node.yml playbook not found")

    env = os.environ.copy()
    cmd = [
        "ansible-playbook",
        str(playbook_path),
        "-e",
        f"target_hardware_address={target_mac}",
        "-e",
        f"ovs_bridge={ovs_bridge}",
        "-e",
        f"sdn_controller_url={controller_url}"
    ]

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=45,
            check=False,
        )
    except Exception as exc:
        raise RuntimeError(f"Ansible playbook execution failed: {exc}")

    result = {
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }
    if completed.returncode != 0:
        raise RuntimeError(f"Ansible returned {completed.returncode}: {completed.stderr.strip()}")

    return result


def _run_quarantine(target_mac, ovs_bridge, controller_url):
    ActiveMitigationStatus.active = True
    ActiveMitigationStatus.last_target = target_mac
    ActiveMitigationStatus.last_action = "Quarantine invocation started"
    ActiveMitigationStatus.last_error = None

    try:
        ansible_result = _run_ansible_playbook(target_mac, ovs_bridge, controller_url)
        ActiveMitigationStatus.last_result = f"Ansible playbook completed: {ansible_result['returncode']}"

        try:
            status_code, body = _post_to_sdn_controller(controller_url, target_mac)
            ActiveMitigationStatus.last_result += f"; SDN controller responded {status_code}"
        except Exception as inner_exc:
            ActiveMitigationStatus.last_result += f"; SDN REST hook failed: {inner_exc}"

    except Exception as exc:
        ActiveMitigationStatus.last_error = str(exc)
        ActiveMitigationStatus.last_result = "Quarantine failed"

    time.sleep(0.5)
    ActiveMitigationStatus.active = False


def trigger_quarantine(target_mac, ovs_bridge="virbr0", controller_url="http://127.0.0.1:8080/stats/flowentry/add"):
    thread = threading.Thread(
        target=_run_quarantine,
        args=(target_mac, ovs_bridge, controller_url),
        daemon=True,
    )
    thread.start()
    return thread
