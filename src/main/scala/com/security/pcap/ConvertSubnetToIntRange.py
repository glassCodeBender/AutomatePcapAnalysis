import pandas as pd
import ipaddress

def start_ipaddr(ip):
    xs = ipaddress.ip_network(ip)

    # First ip address in subnet
    return xs[0]

def end_ipaddr(ip):
    xs = ipaddress.ip_network(ip)
    
    # Last ip address in subnet
    return xs[-1]

def ip_int(ip):
    arr = str(ip).split('.')
    octet1 = int(arr[0]) * 16777216
    octet2 = int(arr[1]) * 65536
    octet3 = int(arr[2]) * 256
    octet4 = int(arr[3])
    combine = octet1 + octet2 + octet3 + octet4
    return combine

df = pd.read_csv("IP2Loc_Data.csv", sep=',', low_memory=True)

df.drop(['is_anonymous_proxy', 'is_satellite_provider'], axis=1, inplace=True )

df['start_ip'] = df['network'].apply(start_ipaddr)

df['end_ip'] = df['network'].apply(end_ipaddr)

df['start_ipint'] = df['start_ip'].apply(ip_int)

df['end_ipint'] = df['end_ip'].apply(ip_int)

df.drop(['start_range', 'end_range', 'network', 'start_ip', 'end_ip', 'registered_metro_code'], axis=1, inplace=True)

df.to_csv("IpGeoLocNew.csv", sep=',')
