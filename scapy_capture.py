import threading
import time
from pathlib import Path

try:
    from scapy.all import sniff, Dot11, RadioTap
except ImportError:
    sniff = None
    Dot11 = None
    RadioTap = None


def is_scapy_available():
    return sniff is not None and Dot11 is not None


def _process_packet(packet):
    if not packet.haslayer(Dot11):
        return None

    dot11 = packet.getlayer(Dot11)
    frame_type = dot11.type
    subtype = dot11.subtype
    rssi = None
    if packet.haslayer(RadioTap) and hasattr(packet.getlayer(RadioTap), 'dBm_AntSignal'):
        rssi = packet.dBm_AntSignal

    record = {
        'SSID': dot11.info.decode(errors='ignore') if hasattr(dot11, 'info') else None,
        'BSSID': dot11.addr3,
        'Source': dot11.addr2,
        'Destination': dot11.addr1,
        'FrameType': frame_type,
        'Subtype': subtype,
        'RSSI': rssi,
        'Deauth': int(frame_type == 0 and subtype == 12),
    }
    return record


def _sniff_worker(interface, packet_count, timeout, output_path):
    if sniff is None:
        raise RuntimeError("Scapy is not installed")

    packets = sniff(iface=interface, count=packet_count, timeout=timeout, monitor=True)
    records = []
    for packet in packets:
        record = _process_packet(packet)
        if record:
            records.append(record)

    if records and output_path:
        Path(output_path).write_text(str(records), encoding='utf-8')
    return records


def run_scapy_sniffer(interface='wlan0', packet_count=100, timeout=20, output_path='scapy_capture.log'):
    thread = threading.Thread(
        target=_sniff_worker,
        args=(interface, packet_count, timeout, output_path),
        daemon=True,
    )
    thread.start()
    return thread
