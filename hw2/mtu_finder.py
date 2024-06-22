import sys
from scapy.all import IP, ICMP, sr1, send
from scapy.config import conf
import validators


def check_host_reachable(destination):
    try:
        packet = IP(dst=destination) / ICMP()
        response = sr1(packet, timeout=2, verbose=False)
        return response is not None
    except Exception as e:
        print(f"Error checking host reachability: {e}")
        return False


def find_min_mtu(destination):
    low, high = 28, 1500
    mtu = low

    while low <= high:
        mid = (low + high) // 2
        packet = IP(dst=destination, flags=2) / ICMP() / ("X" * (mid - 28))
        response = sr1(packet, timeout=2, verbose=False)

        if response is None or (
            response.haslayer(ICMP)
            and response.getlayer(ICMP).type == 3
            and response.getlayer(ICMP).code == 4
        ):
            high = mid - 1
        else:
            mtu = mid
            low = mid + 1

    return mtu


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)

    destination = sys.argv[1]
    valid = (
        validators.ipv4(destination)
        or validators.ipv6(destination)
        or validators.domain(destination)
    )

    if not valid:
        print("Invalid destination. Please enter a valid IP address or domain name.")
        sys.exit(1)

    if not check_host_reachable(destination):
        print(f"Host {destination} is not reachable or ICMP is blocked.")
        sys.exit(1)

    conf.verb = 0
    min_mtu = min(find_min_mtu(destination), 1500)
    print(f"The minimum MTU to {destination} is {min_mtu}")
