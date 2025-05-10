import yaml
import requests
import base64
import urllib.parse


def get_urls():
    data = yaml.safe_load(requests.get("https://raw.githubusercontent.com/byrisk/Node/refs/heads/main/config.yaml").content)
    return [data["proxy-providers"][item]["url"] for item in data["proxy-providers"]]


def get_proxies(url):
    data = yaml.safe_load(requests.get(url).content)
    return len(data.get("proxies", [])), clash_to_v2ray(data)


def clash_to_v2ray(clash_config):
    """
    Converts Clash proxy definitions to V2Ray compatible URL format.

    Args:
      clash_config: A dictionary containing Clash proxy configurations.

    Returns:
      A list of V2Ray URLs.
    """
    v2ray_urls = []
    for proxy in clash_config.get('proxies', []):
        try:
            proxy_type = proxy.get('type').lower()
            if proxy_type == 'vmess':
                v2ray_urls.append(convert_vmess(proxy))
            elif proxy_type == 'vless':
                v2ray_urls.append(convert_vless(proxy))
            elif proxy_type == 'trojan':
                v2ray_urls.append(convert_trojan(proxy))
            elif proxy_type == 'ss':
                v2ray_urls.append(convert_shadowsocks(proxy))
            elif proxy_type == 'ssr':
                v2ray_urls.append(convert_shadowsocksr(proxy))
            elif proxy_type == 'hysteria':
                v2ray_urls.append(convert_hysteria(proxy))
            elif proxy_type == 'hysteria2':
                v2ray_urls.append(convert_hysteria2(proxy))
            elif proxy_type == 'socks5':
                v2ray_urls.append(convert_socks(proxy))
            elif proxy_type == 'http':
                v2ray_urls.append(convert_http(proxy))
            elif proxy_type == 'tuic':
                v2ray_urls.append(convert_tuic(proxy))
            else:
                print(f"Unsupported proxy type: {proxy_type}")
        except Exception as e:
            print(f"Error converting proxy {proxy.get('name', 'Unnamed')}: {e}")
    return v2ray_urls


def convert_vmess(proxy):
    """Converts a VMess proxy to a V2Ray URL."""
    # Mandatory parameters
    uuid = proxy.get('uuid')
    address = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', 'VMess')
    cipher = proxy.get('cipher', 'auto')
    alter_id = proxy.get('alterId', '0')
    network = proxy.get('network', 'tcp')
    tls = proxy.get('tls', False)
    skip_cert_verify = proxy.get('skip-cert-verify', False)
    sni = proxy.get('sni', '')
    ws_opts = proxy.get('ws-opts', {})
    ws_path = ws_opts.get('path', '') if ws_opts else ''
    ws_headers = ws_opts.get('headers', {}) if ws_opts else {}
    ws_host = ws_headers.get('Host', '') if ws_headers else ''

    # Base64 encode the config
    config = {
        "v": "2",
        "ps": name,
        "add": address,
        "port": port,
        "id": uuid,
        "aid": alter_id,
        "type": "none",  # Assuming type is 'none'. Adapt if necessary.
        "scy": cipher,
        "net": network,
        "tls": tls and "tls" or "",
        "sni": sni,
        'path': ws_path,
        'host': ws_host

    }
    if network == 'ws':
        config["host"] = ws_host
        config["path"] = ws_path
    config_str = urllib.parse.quote(str(config))
    config_str = config_str.replace("'", "\"")
    json_str_bytes = config_str.encode("ascii")
    base64_bytes = base64.b64encode(json_str_bytes)
    base64_string = base64_bytes.decode("ascii")
    return f"vmess://{base64_string}"


def convert_vless(proxy):
    """Converts a VLESS proxy to a V2Ray URL."""
    uuid = proxy.get('uuid')
    address = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', 'VLESS')
    tls = proxy.get('tls', False)
    sni = proxy.get('sni', '')
    network = proxy.get('network', 'tcp')
    ws_opts = proxy.get('ws-opts', {})
    ws_path = ws_opts.get('path', '')
    ws_headers = ws_opts.get('headers', {}) if ws_opts else {}
    ws_host = ws_headers.get('Host', '') if ws_headers else ''
    client_fingerprint = proxy.get('client-fingerprint', '')
    flow = proxy.get('flow', '')
    skip_cert_verify = proxy.get('skip-cert-verify', False)

    # Reality settings
    reality_opts = proxy.get('reality-opts', {})
    pb_key = reality_opts.get('public-key', '')
    short_id = reality_opts.get('short-id', '')

    # Construct the VLESS URL
    vless_url = f"vless://{uuid}@{address}:{port}"
    params = {
        "encryption": "none",  # VLESS doesn't use encryption
        "security": tls and "tls" or "none",

    }

    # Add network settings
    if network == 'ws':
        params["type"] = "ws"
        params["path"] = ws_path
        params["host"] = ws_host

    if sni:
        params['sni'] = sni
    if client_fingerprint:
        params['fp'] = client_fingerprint
    if flow:
        params['flow'] = flow  # xtls-rprx-vision

    if pb_key:
        params['pbk'] = pb_key
        params['sid'] = short_id
        params['security'] = "reality"  # If reality is used, force tls and reality security
        params["encryption"] = "none"

    # Encode parameters to URL
    params_str = urllib.parse.urlencode(params)
    vless_url += f"?{params_str}#{name}"
    return vless_url


def convert_trojan(proxy):
    """Converts a Trojan proxy to a V2Ray URL."""
    password = proxy.get('password')
    address = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', 'Trojan')
    sni = proxy.get('sni', '')
    network = proxy.get('network', 'tcp')
    ws_opts = proxy.get('ws-opts', {})
    ws_path = ws_opts.get('path', '')
    ws_headers = ws_opts.get('headers', {}) if ws_opts else {}
    ws_host = ws_headers.get('Host', '') if ws_headers else ''
    skip_cert_verify = proxy.get('skip-cert-verify', False)
    client_fingerprint = proxy.get('client-fingerprint', '')
    alpn = proxy.get('alpn', '')

    trojan_url = f"trojan://{password}@{address}:{port}"
    params = {}

    if network == 'ws':
        params["type"] = "ws"
        params["path"] = ws_path
        params["host"] = ws_host
    if sni:
        params['sni'] = sni
    tls = proxy.get('tls', False)
    if tls:
        params['security'] = 'tls'
    else:
        params['security'] = 'none'
        skip_cert_verify = True  # Force skip cert verify if disable tls
    if skip_cert_verify:
        params['allowInsecure'] = 'true'  # 不安全验证
    if alpn:
        if isinstance(alpn, list):
            params['alpn'] = ','.join(alpn)  # alpn参数

    # Encode parameters to URL
    params_str = urllib.parse.urlencode(params)
    trojan_url += f"?{params_str}#{name}"

    return trojan_url


def convert_shadowsocks(proxy):
    """Converts a Shadowsocks proxy to a V2Ray URL."""
    address = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', 'Shadowsocks')
    password = proxy.get('password')
    cipher = proxy.get('cipher')
    udp = proxy.get('udp', '')

    # Base64 Encode
    userinfo = f"{cipher}:{password}"
    userinfo_bytes = userinfo.encode('ascii')
    base64_bytes = base64.b64encode(userinfo_bytes)
    base64_string = base64_bytes.decode('ascii')

    ss_url = f"ss://{base64_string}@{address}:{port}"
    params = {}
    if udp:
        params["udp"] = 'true'  # Set udp enable flag

    params_str = urllib.parse.urlencode(params)
    ss_url += f"?{params_str}#{name}"

    return ss_url


def convert_shadowsocksr(proxy):
    # Fetch information from the proxy
    server = proxy.get('server')
    port = str(proxy.get('port'))
    password = proxy.get('password')
    method = proxy.get('cipher')
    protocol = proxy.get('protocol')
    obfs = proxy.get('obfs')
    protocolparam = proxy.get('protocol-param', '')
    obfsparam = proxy.get('obfs-param', '')
    name = proxy.get('name', 'ShadowsocksR')
    udp = proxy.get('udp', False) if proxy.get('udp') is not None else False

    # Format user info
    userinfo = f"{method}:{password}@{server}:{port}"
    b64_userinfo = base64.b64encode(userinfo.encode()).decode()

    # Prepare parameters
    params = {
        'protocol': protocol,
        'obfs': obfs,
        'protoparam': base64.b64encode(protocolparam.encode()).decode(),
        'obfsparam': base64.b64encode(obfsparam.encode()).decode(),
        'remarks': base64.b64encode(name.encode()).decode(),
        'group': base64.b64encode('default'.encode()).decode(),
        'udpport': '0',  # Assuming default UDP port is 0, customize if needed
        'uot': '0'  # Assuming default UOT is 0, customize if needed
    }
    if udp:
        params['udp'] = 'true'
    # Encode parameters to URL
    param_str = urllib.parse.urlencode(params)
    ssr_url = f"ssr://{b64_userinfo}/?{param_str}#{name}"

    return ssr_url


def convert_hysteria(proxy):
    """Converts a Hysteria proxy to a V2Ray URL."""
    address = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', 'Hysteria')
    password = proxy.get('auth_str') or proxy.get('auth-str')  # Handle both keys
    sni = proxy.get('sni', address)  # Use server as SNI if not provided
    skip_cert_verify = proxy.get('skip-cert-verify', True)
    alpn = proxy.get('alpn', ['h3'])  # Use h3 if no alpn
    protocol = proxy.get('protocol', 'udp')
    params = {}
    if sni:
        params['sni'] = sni
    if protocol:
        params['protocol'] = protocol

    if skip_cert_verify:
        params['allowInsecure'] = 'true'

    if alpn:
        if isinstance(alpn, list):
            params['alpn'] = ','.join(alpn)  # alpn参数
    up = proxy.get('up', '')
    down = proxy.get('down', '')
    if up:
        params['up'] = up
    if down:
        params['down'] = down
    # Encode parameters to URL
    params_str = urllib.parse.urlencode(params)
    hysteria_url = f"hysteria://{address}:{port}?{params_str}#{name}"
    return hysteria_url


def convert_hysteria2(proxy):
    """Converts a Hysteria2 proxy to a V2Ray URL."""
    address = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', 'Hysteria2')
    password = proxy.get('password')
    sni = proxy.get('sni', address)
    skip_cert_verify = proxy.get('skip-cert-verify', True)
    obfs = proxy.get('obfs', '')
    obfs_password = proxy.get('obfs-password', '')
    alpn = proxy.get('alpn', ['h3'])
    up = proxy.get('up', '')
    down = proxy.get('down', '')
    hysteria2_url = f"hysteria2://{address}:{port}"
    params = {}
    if password:
        params['auth'] = password
    if sni:
        params['sni'] = sni
    if skip_cert_verify:
        params['allowInsecure'] = 'true'
    if obfs:
        params['obfs'] = obfs
    if obfs_password:
        params['obfs-password'] = obfs_password
    if alpn:
        if isinstance(alpn, list):
            params['alpn'] = ','.join(alpn)  # alpn参数
    if up:
        params['up'] = up
    if down:
        params['down'] = down

    params_str = urllib.parse.urlencode(params)
    hysteria2_url += f"?{params_str}#{name}"

    return hysteria2_url


def convert_socks(proxy):
    """Converts a SOCKS proxy to a V2Ray URL."""
    address = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', 'SOCKS')
    tls = proxy.get('tls', False)
    sni = proxy.get('sni', '')
    # Construct the SOCKS URL
    socks_url = f"socks://{address}:{port}"
    params = {}
    if tls:
        params['security'] = 'tls'  # tls
        sni = proxy.get('sni', '')
        if sni:
            params['sni'] = sni
        skip_cert_verify = proxy.get('skip-cert-verify', '')
        if skip_cert_verify:
            params['allowInsecure'] = 'true'

    # Encode parameters to URL
    params_str = urllib.parse.urlencode(params)
    socks_url += f"?{params_str}#{name}"
    return socks_url


def convert_http(proxy):
    """Converts a HTTP proxy to a V2Ray URL."""
    address = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', 'HTTP')
    tls = proxy.get('tls', False)
    sni = proxy.get('sni', '')
    username = proxy.get('username', '')
    password = proxy.get('password', '')

    http_url = f"http://{address}:{port}"
    params = {}

    if (username and password):
        userinfo = f"{username}:{password}"
        b64_userinfo = base64.b64encode(userinfo.encode()).decode()
        params['headerType'] = 'http'
        params['Authorization'] = f"Basic {b64_userinfo}"

    if tls:
        params['security'] = 'tls'  # tls
        sni = proxy.get('sni', '')
        if sni:
            params['sni'] = sni
        skip_cert_verify = proxy.get('skip-cert-verify', '')
        if skip_cert_verify:
            params['allowInsecure'] = 'true'
            # Encode parameters to URL
    params_str = urllib.parse.urlencode(params)
    http_url += f"?{params_str}#{name}"

    return http_url


def convert_tuic(proxy):
    """Converts a Hysteria proxy to a V2Ray URL."""
    address = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', 'tuic')
    password = proxy.get('password')
    sni = proxy.get('sni', '')  # Use server as SNI if not provided

    version = proxy.get('version', 5)
    skip_cert_verify = proxy.get('skip-cert-verify', True)
    alpn = proxy.get('alpn', '')
    udp = proxy.get('udp', True)
    uuid = proxy.get('uuid')
    params = {}
    if password:
        params['password'] = password
    if sni:
        params['sni'] = sni
    if version:
        params['version'] = version
    if skip_cert_verify:
        params['allowInsecure'] = 'true'
    if udp is False:
        params['disable-udp'] = 'true'
    if uuid:
        params['uuid'] = uuid
    # Encode parameters to URL
    if alpn:
        if isinstance(alpn, list):
            params['alpn'] = ','.join(alpn)  # alpn参数
    params_str = urllib.parse.urlencode(params)
    tuic_url = f"tuic://{address}:{port}?{params_str}#{name}"
    return tuic_url


# Load Clash configuration from YAML file (or string)
def load_config(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            return config
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return None
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return None


if __name__ == '__main__':
    for url in get_urls():
        total, proxies = get_proxies(url)
        print(f'total: {total}, proxies: {proxies}')

