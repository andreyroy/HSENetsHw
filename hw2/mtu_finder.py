import sys
from scapy.all import IP, ICMP, sr1
from scapy.config import conf
import validators

def check_host_reachable(destination):
    try:
        packet = IP(dst=destination)/ICMP()
        response = sr1(packet, timeout=2, verbose=False)
        return response is not None
    except Exception:
        return False

def find_min_mtu(destination):
    low = 28  # Minimal IP packet size (28 bytes for headers alone)
    high = 1500
    mtu = low

    while low <= high:
        mid = (low + high) // 2
        packet = IP(dst=destination, flags="DF")/ICMP()/("X"*(mid-28))
        response = sr1(packet, timeout=2, verbose=False)
        
        if response is None:
            high = mid - 1
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code == 4:
            high = mid - 1
        else:
            mtu = mid
            low = mid + 1
    return mtu

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python mtu_finder.py <destination>")
        sys.exit(1)
    
    destination = sys.argv[1]
    
    try:
        is_valid_ip = validators.ipv4(destination) or validators.ipv6(destination)
        is_valid_domain = validators.domain(destination)
        if not destination or not (is_valid_ip or is_valid_domain):
            raise ValueError("Invalid destination")
    except ValueError:
        print("Invalid destination. Please enter a valid IP address or domain name.")
        sys.exit(1)
    
    conf.verb = 0
    try:
        if not check_host_reachable(destination):
            print(f"Host {destination} is not reachable, ICMP is blocked, or the name is invalid.")
            sys.exit(1)
        
        min_mtu = find_min_mtu(destination) + 28  # Adding headers size to the final MTU
        print(f"The minimum MTU to {destination} is {min_mtu}")
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)