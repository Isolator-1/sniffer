import ipaddress

ipv6_address = "2400:3200:baba::1"

try:
    ip = ipaddress.ip_address(ipv6_address)
    print(f"{ipv6_address} is a valid IPv6 address.")
except ValueError:
    print(f"{ipv6_address} is not a valid IPv6 address.")

# 2400:3200:baba::1 is a valid IPv6 address.