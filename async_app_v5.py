import os
import base64
import aiohttp
import asyncio
import requests
import logging
import threading
from flask import Flask, jsonify, render_template, send_from_directory, request

app = Flask(__name__)

device_username = ""
device_password = ""

device_ip_addresses = []
device_cookies = {}
cache = {}
initial_fetch_completed = False
all_network_values_global = {}

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.DEBUG)

def parse_ip_addresses(ip_input):
    ip_addresses = []
    for ip_range in ip_input.split(','):
        ip_range = ip_range.strip()
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            start_parts = start_ip.split('.')
            end_parts = end_ip.split('.')
            for i in range(int(start_parts[-1]), int(end_parts[-1]) + 1):
                ip_address = '.'.join(start_parts[:-1] + [str(i)])
                ip_addresses.append(ip_address)
        else:
            ip_addresses.append(ip_range)
    return ip_addresses

async def get_data():
    global initial_fetch_completed, all_network_values_global
    ip_input = request.json.get('ip_addresses', '')
    device_ip_addresses = parse_ip_addresses(ip_input)
    if not initial_fetch_completed or device_ip_addresses != all_network_values_global.get('ip_addresses', []):
        all_network_values_global = await fetch_all_data(device_ip_addresses)
        all_network_values_global['ip_addresses'] = device_ip_addresses
        initial_fetch_completed = True
    return jsonify(all_network_values_global)

async def fetch_device_data(session, ip, device_username, device_password):
    url = f"https://{ip}/api/rest/v2/batch"
    headers = {}
    credentials = f"{device_username}:{device_password}"
    base64_credentials = base64.b64encode(credentials.encode()).decode()
    headers["Authorization"] = f"Basic {base64_credentials}"
    headers["Content-Type"] = "application/json"
    body = {
        "requests":[
            {
                "id": "Local BACNet Data",
                "url": "/api/rest/v2/services/bacnet/local/objects/devices?$select=*($select=object-name&$select=model-name&$select=description&$select=location&$select=active-cov-subscriptions($select=*($select=recipient-process($select=recipient)&$select=monitored-property-reference($select=object-identifier))))"
            },
            {
                "id": "Local GFX Network Values",
                "method": "GET",
                "url": "/api/rest/v2/services/gfx/configuration?$select=network*"
            },
            {
                "id": "Remote BACnet Data",
                "url": "/api/rest/v2/services/bacnet/remote/devices?$select=*($select=objects($select=*($select=*($select=object-name)))&$select=local-name&$select=model-name&$select=description&$select=location&$select=connection-status)"
            },
            {
                "id": "Remote Modbus Data",
                "method": "GET",
                "url": "/api/rest/v2/services/modbus/devices?$select=*($select=address($select=ip)&$select=points($select=*($select=key))&$select=status)"
            },
            {
                "id": "Local GFX Modbus Values",
                "method": "GET",
                "url": "/api/rest/v2/services/gfx/configuration?$select=modbus-device*"
            },
            {
                "id": "IOT Connections",
                "method": "GET",
                "url": "/api/rest/v2/services/iot/connections?$select=*($select=key&$select=status&$select=last-error)"
            },
            {
                "id": "Remote Tunnel Connections",
                "method": "GET",
                "url": "/api/rest/v2/services/remote-tunneling/connections?$select=*($select=key&$select=enabled&$select=links)"
            },
            {
                "id": "MQTT Broker Connections",
                "method": "GET",
                "url": "/api/rest/v2/services/mqtt/connections?$select=*($select=key&$select=enabled&$select=broker-address)"
            },
            {
                "id": "Weather Connections",
                "method": "GET",
                "url": "/api/rest/v2/services/weather/locations?$select=*($select=provider&$select=report($select=status-message&$select=enabled&$select=status&$select=last-success))"
            },
            {
                "id": "Internet & NTP Connection",
                "method": "GET",
                "url": "/api/rest/v2/services/platform?$select=time($select=ntp)&$select=network($select=connected-to-internet&$select=public-ip)"
            },
            {
                "id": "BBMD Table Connections",
                "method": "GET",
                "url": "/api/rest/v2/services/bacnet?$select=communication($select=network($select=ports($select=*($select=bbmd-broadcast-distribution-table&$select=enabled))))"
            },
            {
                "id": "Email Server Connections",
                "method": "GET",
                "url": "/api/rest/v2/services/email/accounts?$select=*($select=key&$select=hostname&$select=enabled)"
            },
            {
                "id": "Scheduled Tasks",
                "method": "GET",
                "url": "/api/rest/v2/services/events/tasks?$select=*($select=recipients($select=*($select=last-result))&$select=key)"
            }
        ]
    }
    try:
        async with session.post(url, headers=headers, json=body, ssl=False) as response:
            if response.status == 200:
                data = await response.json()
                structured_data = {}
                for response in data.get("responses", []):
                    response_id = response.get("id")
                    response_body = response.get("body")
                    structured_data[response_id] = response_body
                return {ip: structured_data}
            else:
                print(f"Error fetching data from {ip}: {response.status}")
                return None
    except aiohttp.ClientError as e:
        print(f"Error fetching data from {ip}: {e}")
        return None

def remove_entries(d, keys_to_remove, substrings_to_remove=None):
    """
    Recursively remove specified keys and any sections containing an 'error' key.
    
    Args:
        d (dict): The dictionary to clean.
        keys_to_remove (set): A set of keys to remove.
        substrings_to_remove (set, optional): A set of substrings; any key containing any of these substrings will be removed.
    
    Returns:
        dict: The cleaned dictionary.
    """
    if not isinstance(d, dict):
        return d
    new_dict = {}
    for key, value in d.items():
        key_str = str(key)
        
        # Skip sections where the body contains an 'error' key
        if isinstance(value, dict) and "error" in value:
            logging.debug(f"Removing section '{key_str}' due to presence of 'error'.")
            continue  # Skip this key entirely
        
        # Skip keys that are in keys_to_remove or contain any substrings to remove
        if key_str in keys_to_remove:
            logging.debug(f"Removing key '{key_str}' as it is in keys_to_remove.")
            continue
        if substrings_to_remove and any(substring in key_str for substring in substrings_to_remove):
            logging.debug(f"Removing key '{key_str}' as it contains one of the substrings to remove.")
            continue
        
        # Recursively clean nested dictionaries
        if isinstance(value, dict):
            cleaned_value = remove_entries(value, keys_to_remove, substrings_to_remove)
            if cleaned_value:  # Only add non-empty dictionaries
                new_dict[key] = cleaned_value
        else:
            new_dict[key] = value
    return new_dict

def create_links(data):
    """
    Create 'Links' and 'Nodes' structures from the fetched data.
    
    Args:
        data (dict): The cleaned data after removing entries with errors.
    
    Returns:
        dict: The structured data containing 'Links' and 'Nodes'.
    """
    links = {
        "Network Values": {},
        "Objects": {}
    }
    nodes = {}
    keys_to_ignore = {"4194303", "4194304"}

    for ip, content in data.items():
        logging.debug(f"Processing IP: {ip}")
        
        # Track device_ids for the current IP
        current_ip_device_ids = set()
        
        # Process Local BACNet Data
        if "Local BACNet Data" in content:
            for device_id, device_data in content["Local BACNet Data"].items():
                current_ip_device_ids.add(device_id)
                
                if device_id not in links["Objects"]:
                    links["Objects"][device_id] = {}
                if device_id not in links["Network Values"]:
                    links["Network Values"][device_id] = {}
                
                nodes[device_id] = {
                    "description": device_data.get("description", ""),
                    "local-name": device_data.get("object-name", ""),
                    "location": device_data.get("location", ""),
                    "model-name": device_data.get("model-name", ""),
                    "ip-address": ip,
                    "node-type": "bacnet_local"
                }
                logging.debug(f"Added node for device_id: {device_id}")

                # Process Remote BACnet Data
                if "Remote BACnet Data" in content:
                    for remote_id, remote_data in content["Remote BACnet Data"].items():
                        if remote_id in keys_to_ignore:
                            logging.debug(f"Ignoring remote_id: {remote_id}")
                            continue
                        if remote_id == device_id:
                            links["Objects"][device_id][remote_id] = remote_data
                        else:
                            if remote_id not in links["Objects"][device_id]:
                                links["Objects"][device_id][remote_id] = {"objects": remote_data.get("objects", {})}
                        
                        count = count_object_names(links["Objects"][device_id][remote_id].get("objects", {}))
                        links["Objects"][device_id][remote_id]["count"] = count
                        links["Objects"][device_id][remote_id]["Connection-Status"] = str(remote_data.get("connection-status", {})).title()
                        links["Objects"][device_id][remote_id]["node-type"] = "bacnet_remote"
                        logging.debug(f"Linked remote_id: {remote_id} to device_id: {device_id}")

        # Process Local GFX Network Values
        if "Local GFX Network Values" in content:
            for gfx_key, gfx_values in content["Local GFX Network Values"].items():
                for gfx_value in gfx_values:
                    parts = gfx_value.split('/')
                    if len(parts) > 5 and parts[2] == 'bacnet' and parts[3] == 'remote' and parts[4] == 'devices':
                        if not current_ip_device_ids:
                            logging.warning(f"No local device found for IP {ip} while processing GFX Network Values.")
                            continue
                        local_device_id = next(iter(current_ip_device_ids))  # Assuming one local device per IP
                        remote_device_id = parts[5]
                        if remote_device_id in keys_to_ignore:
                            logging.debug(f"Ignoring remote_device_id: {remote_device_id}")
                            continue
                        object_type = parts[7]
                        object_id = parts[8]
                        if local_device_id not in links["Network Values"]:
                            links["Network Values"][local_device_id] = {}
                        if remote_device_id not in links["Network Values"][local_device_id]:
                            links["Network Values"][local_device_id][remote_device_id] = {"objects": {}}
                        if object_type not in links["Network Values"][local_device_id][remote_device_id]["objects"]:
                            links["Network Values"][local_device_id][remote_device_id]["objects"][object_type] = {}
                        if object_id not in links["Network Values"][local_device_id][remote_device_id]["objects"][object_type]:
                            
                            object_name = ""
                            if (local_device_id in links["Objects"] and
                                remote_device_id in links["Objects"][local_device_id] and
                                "objects" in links["Objects"][local_device_id][remote_device_id] and
                                object_type in links["Objects"][local_device_id][remote_device_id]["objects"] and
                                object_id in links["Objects"][local_device_id][remote_device_id]["objects"][object_type]):
                                object_name = links["Objects"][local_device_id][remote_device_id]["objects"][object_type][object_id].get("object-name", "")
                            else:
                                object_name = "N/A"  
                            links["Network Values"][local_device_id][remote_device_id]["objects"][object_type][object_id] = {"object-name": object_name}
                            logging.debug(f"Added object {object_id} of type {object_type} with name '{object_name}'")
                        count = count_object_names(links["Network Values"][local_device_id][remote_device_id].get("objects", {}))
                        links["Network Values"][local_device_id][remote_device_id]["count"] = count
                        
                        if remote_device_id in content.get("Remote BACnet Data", {}):
                            remote_data = content["Remote BACnet Data"][remote_device_id]
                            links["Network Values"][local_device_id][remote_device_id]["Connection-Status"] = remote_data.get("connection-status", {})
                            logging.debug(f"Set Connection-Status for remote_device_id: {remote_device_id}")

        # Process Remote Modbus Data
        if "Remote Modbus Data" in content:
            for modbus_key, modbus_value in content["Remote Modbus Data"].items():
                if modbus_value != "error" and modbus_value:
                    nodes[modbus_key] = {
                        "ip-address": modbus_value.get("address", {}).get("ip", ""),
                        "node-type": "modbus_remote",
                        "status": modbus_value.get("status", "")
                    }
                    logging.debug(f"Added node for modbus_key: {modbus_key}")
                    
                    if not current_ip_device_ids:
                        logging.warning(f"No local device found for IP {ip} while processing Remote Modbus Data.")
                        continue
                    local_device_id = next(iter(current_ip_device_ids))  # Assuming one local device per IP
                    if local_device_id not in links["Objects"]:
                        links["Objects"][local_device_id] = {}
                    modbus_value_cleaned = {k: v for k, v in modbus_value.items() if k not in {"address", "ip"}}
                    if "points" in modbus_value_cleaned:
                        for point_key, point_value in modbus_value_cleaned["points"].items():
                            if "key" in point_value:
                                point_value["object-name"] = point_value.pop("key")
                    
                    links["Objects"][local_device_id][modbus_key] = modbus_value_cleaned                   
                    count = len(modbus_value_cleaned.get("points", {}))
                    links["Objects"][local_device_id][modbus_key]["count"] = count
                    links["Objects"][local_device_id][modbus_key]["Connection-Status"] = str(modbus_value.get("status", "")).title()
                    links["Objects"][local_device_id][modbus_key]["node-type"] = "modbus_remote"
                    logging.debug(f"Linked modbus_key: {modbus_key} to device_id: {local_device_id}")

        # Process Local GFX Modbus Values
        if "Local GFX Modbus Values" in content:
            for gfx_key, gfx_values in content["Local GFX Modbus Values"].items():
                if not current_ip_device_ids:
                    logging.warning(f"No local device found for IP {ip} while processing Local GFX Modbus Values.")
                    continue
                local_device_id = next(iter(current_ip_device_ids))  # Assuming one local device per IP
                if local_device_id not in links["Network Values"]:
                    links["Network Values"][local_device_id] = {}
                for gfx_value in gfx_values:
                    parts = gfx_value.split('/')
                    if len(parts) > 3 and parts[2] == 'modbus' and parts[3] == 'devices':
                        device_name = parts[4].replace('%20', ' ')
                        if device_name not in links["Network Values"][local_device_id]:
                            links["Network Values"][local_device_id][device_name] = {"count": 0}                       
                        links["Network Values"][local_device_id][device_name]["count"] += 1
                        logging.debug(f"Incremented count for device_name: {device_name}")
                    if device_name in content.get("Remote Modbus Data", {}):
                        remote_data = content["Remote Modbus Data"][device_name]
                        links["Network Values"][local_device_id][device_name]["Connection-Status"] = remote_data.get("status", {})
                        logging.debug(f"Set Connection-Status for device_name: {device_name}")

        # Process IOT Connections
        if "IOT Connections" in content:
            for iot_key, iot_value in content["IOT Connections"].items():
                if iot_value != "error" and iot_value:
                    nodes[iot_key] = {
                        "description": "IOT Connection",
                        "model-name": "iot_hub",
                        "node-type": "iot_remote",
                        "connection-status": iot_value.get("status", "")
                    }
                    logging.debug(f"Added node for iot_key: {iot_key}")
                    
                    for device_id in current_ip_device_ids:
                        links["Objects"][device_id][iot_key] = {}
                        links["Objects"][device_id][iot_key]["count"] = 1
                        links["Objects"][device_id][iot_key]["Connection-Status"] = "Online" if iot_value.get("status") == "Connected" else "Offline"
                        logging.debug(f"Linked iot_key: {iot_key} to device_id: {device_id}")

        # Process Remote Tunnel Connections
        if "Remote Tunnel Connections" in content:
            remote_tunnel_data = content.get("Remote Tunnel Connections", {})
            for rmt_key, rmt_value in remote_tunnel_data.items():
                if rmt_value != "error" and rmt_value:
                    nodes[rmt_key] = {
                        "description": "Remote Tunnel Connection",
                        "model-name": "rmt_tunnel",
                        "node-type": "rmt_remote",
                        "connection-status": "Online" if rmt_value.get("enabled") else "Offline"
                    }
                    logging.debug(f"Added node for remote tunnel: {rmt_key}")
                    
                    for device_id in current_ip_device_ids:
                        tunnels = []
                        rmt_links = rmt_value.get("links")
                        if rmt_links:
                            value = rmt_links.get("$value")
                            if value:
                                connection = value.get("127.0.0.1:443")
                                if connection:
                                    remote = connection.get("remote")
                                    if remote:
                                        tunnels = remote.get("https", [])
                        links["Objects"][device_id][rmt_key] = {
                            "Tunnels": tunnels
                        }
                        count = len(tunnels)
                        links["Objects"][device_id][rmt_key]["count"] = count
                        links["Objects"][device_id][rmt_key]["Connection-Status"] = "Online" if rmt_value.get("enabled") else "Offline"
                        logging.debug(f"Linked remote tunnel: {rmt_key} to device_id: {device_id} with {count} tunnels")

        # Process MQTT Broker Connections
        if "MQTT Broker Connections" in content:
            mqtt_data = content.get("MQTT Broker Connections", {})
            for mqtt_key, mqtt_value in mqtt_data.items():
                if mqtt_value != "error" and mqtt_value:
                    nodes[mqtt_key] = {
                        "description": "MQTT Broker",
                        "model-name": "mqtt_broker",
                        "node-type": "mqtt_remote",
                        "connection-status": "Online" if mqtt_value.get("enabled") else "Offline"
                    }
                    logging.debug(f"Added node for MQTT Broker: {mqtt_key}")
                    
                    for device_id in current_ip_device_ids:
                        links["Objects"][device_id][mqtt_key] = {}
                        links["Objects"][device_id][mqtt_key]["count"] = 1
                        links["Objects"][device_id][mqtt_key]["Connection-Status"] = "Online" if mqtt_value.get("enabled") else "Offline"
                        logging.debug(f"Linked MQTT Broker: {mqtt_key} to device_id: {device_id}")
        
        # Process Weather Connections
        if "Weather Connections" in content:
            weather_data = content.get("Weather Connections", {})
            for weather_key, weather_value in weather_data.items():
                if weather_value != "error" and weather_value:
                    provider_name = weather_value.get("provider", "")
                    provider_name = provider_name.title() if provider_name.lower() == "accuweather" else provider_name
                    nodes[provider_name] = {
                        "description": "Weather Connection",
                        "model-name": "weather_server",
                        "node-type": "weather_remote",
                        "provider": provider_name,
                        "status": weather_value.get("report", {}).get("status", 0),
                    }
                    logging.debug(f"Added node for Weather Connection: {provider_name}")
                    
                    for device_id in current_ip_device_ids:
                        links["Objects"][device_id][provider_name] = {}
                        links["Objects"][device_id][provider_name]["count"] = 1
                        links["Objects"][device_id][provider_name]["Connection-Status"] = "Online" if weather_value.get("report", {}).get("status-message") == "OK" else "Offline"
                        links["Objects"][device_id][provider_name]["Enabled"] = str(weather_value.get("report", {}).get("enabled")).title()
                        links["Objects"][device_id][provider_name]["Last-Success"] = weather_value.get("report", {}).get("last-success")
                        logging.debug(f"Linked Weather Connection: {provider_name} to device_id: {device_id}")

        # Process Internet & NTP Connection
        if "Internet & NTP Connection" in content:
            internet_ntp_data = content.get("Internet & NTP Connection", {})
            internet_data = internet_ntp_data.get("network", {})
            
            if "Local BACNet Data" in content and list(content["Local BACNet Data"].keys()):
                local_device_id = next(iter(current_ip_device_ids))  # Assuming one local device per IP
                internet_node_name = "Internet Connection"
                nodes[internet_node_name] = {
                    "description": "Internet Connection",
                    "model-name": "internet_server",
                    "node-type": "internet_remote",
                    "connection-status": "Online" if internet_data.get("connected-to-internet") else "Offline",
                }
                logging.debug(f"Added node for Internet Connection: {internet_node_name}")
                
                if local_device_id in links["Objects"]:
                    links["Objects"][local_device_id][internet_node_name] = {}
                    count = 1
                    links["Objects"][local_device_id][internet_node_name]["count"] = count
                    links["Objects"][local_device_id][internet_node_name]["Connection-Status"] = "Online" if internet_data.get("connected-to-internet") else "Offline"
                    links["Objects"][local_device_id][internet_node_name]["Public-Ip"] = internet_data.get("public-ip", "")
                    logging.debug(f"Linked Internet Connection to device_id: {local_device_id}")
                
                ntp_data = internet_ntp_data.get("time", {}).get("ntp", {})
                ntp_node_name = "NTP Connection"
                
                nodes[ntp_node_name] = {
                    "description": "TimeSync Server",
                    "model-name": "time_server",
                    "node-type": "ntp_remote",
                    "connection-status": "Online" if ntp_data.get("synchronized") else "Offline",
                }
                logging.debug(f"Added node for NTP Connection: {ntp_node_name}")
                
                if local_device_id in links["Objects"]:
                    links["Objects"][local_device_id][ntp_node_name] = {}
                    count = 1
                    links["Objects"][local_device_id][ntp_node_name]["count"] = count
                    links["Objects"][local_device_id][ntp_node_name]["Connection-Status"] = "Online" if ntp_data.get("synchronized") else "Offline"
                    links["Objects"][local_device_id][ntp_node_name]["System-Servers"] = ntp_data.get("system-servers", [])
                    links["Objects"][local_device_id][ntp_node_name]["Fallback-Servers"] = ntp_data.get("fallback-servers", [])
                    links["Objects"][local_device_id][ntp_node_name]["Enabled"] = str(ntp_data.get("enabled", [])).title()
                    links["Objects"][local_device_id][ntp_node_name]["Active-Server"] = ntp_data.get("active-server", [])
                    logging.debug(f"Linked NTP Connection to device_id: {local_device_id}")

        # Process BBMD Table Connections
        if "BBMD Table Connections" in content:
            bbmd_data = content.get("BBMD Table Connections", {}).get("communication", {}).get("network", {}).get("ports", {})
            primary_bbmd_data = bbmd_data.get("primary", {}).get("bbmd-broadcast-distribution-table", {})
            
            for bbmd_key, bbmd_value in primary_bbmd_data.items():
                bbmd_ip_address = bbmd_value.get("ip", "")
                local_device_id = None
                bbmd_device_id = None
                for ip_inner, device_content in data.items():
                    if ip_inner == bbmd_ip_address:
                        if "Local BACNet Data" in device_content and list(device_content["Local BACNet Data"].keys()):
                            local_device_id = list(device_content["Local BACNet Data"].keys())[0]
                        remote_bacnet_data = device_content.get("Remote BACnet Data", {})
                        if remote_bacnet_data:
                            bbmd_device_id = list(remote_bacnet_data.keys())[0]
                        break
                if local_device_id and bbmd_device_id:
                    if local_device_id not in links["Objects"]:
                        links["Objects"][local_device_id] = {}
                    if bbmd_device_id not in links["Objects"][local_device_id]:
                        links["Objects"][local_device_id][bbmd_device_id] = {}
                    links["Objects"][local_device_id][bbmd_device_id]["bbmd_primary"] = {
                        "port": bbmd_value.get("port", 0),
                        "type": bbmd_value.get("type", "")
                    }
                    links["Objects"][local_device_id][bbmd_device_id]["count"] = links["Objects"][local_device_id][bbmd_device_id].get("count", 0) + 1
                    logging.debug(f"Linked BBMD Primary: {bbmd_key} to device_id: {local_device_id} and bbmd_device_id: {bbmd_device_id}")
                else:
                    bbmd_node_name = f"Primary BBMD-{bbmd_key}"
                    nodes[bbmd_node_name] = {
                        "description": "Primary BBMD Connection",
                        "model-name": "bbmd",
                        "node-type": "bbmd_primary",
                    }
                    logging.debug(f"Added node for Primary BBMD Connection: {bbmd_node_name}")
                    for device_id in current_ip_device_ids:
                        links["Objects"][device_id][bbmd_node_name] = {}
                        links["Objects"][device_id][bbmd_node_name]["count"] = 1
                        links["Objects"][device_id][bbmd_node_name]["Port"] = bbmd_value.get("port", 0)
                        links["Objects"][device_id][bbmd_node_name]["Type"] = bbmd_value.get("type", "")
                        links["Objects"][device_id][bbmd_node_name]["Ip-address"] = bbmd_ip_address
                        links["Objects"][device_id][bbmd_node_name]["Enabled"] = str(bbmd_data.get("primary", {}).get("enabled", {})).title()
                        logging.debug(f"Linked Primary BBMD Connection: {bbmd_node_name} to device_id: {device_id}")

            # Secondary BBMD Table Connections
            secondary_bbmd_data = bbmd_data.get("secondary", {}).get("bbmd-broadcast-distribution-table", {})
            for bbmd_key, bbmd_value in secondary_bbmd_data.items():
                bbmd_ip_address = bbmd_value.get("ip", "")
                local_device_id = None
                bbmd_device_id = None
                for ip_inner, device_content in data.items():
                    if ip_inner == bbmd_ip_address:
                        if "Local BACNet Data" in device_content and list(device_content["Local BACNet Data"].keys()):
                            local_device_id = list(device_content["Local BACNet Data"].keys())[0]
                        remote_bacnet_data = device_content.get("Remote BACnet Data", {})
                        if remote_bacnet_data:
                            bbmd_device_id = list(remote_bacnet_data.keys())[0]
                        break
                if local_device_id and bbmd_device_id:
                    if local_device_id not in links["Objects"]:
                        links["Objects"][local_device_id] = {}
                    if bbmd_device_id not in links["Objects"][local_device_id]:
                        links["Objects"][local_device_id][bbmd_device_id] = {}
                    links["Objects"][local_device_id][bbmd_device_id]["bbmd_secondary"] = {
                        "port": bbmd_value.get("port", 0),
                        "type": bbmd_value.get("type", "")
                    }
                    links["Objects"][local_device_id][bbmd_device_id]["count"] = links["Objects"][local_device_id][bbmd_device_id].get("count", 0) + 1
                    logging.debug(f"Linked BBMD Secondary: {bbmd_key} to device_id: {local_device_id} and bbmd_device_id: {bbmd_device_id}")
                else:
                    bbmd_node_name = f"Secondary BBMD Connection {bbmd_key}"
                    nodes[bbmd_node_name] = {
                        "description": "Secondary BBMD Connection",
                        "model-name": "bbmd",
                        "node-type": "bbmd_secondary",
                    }
                    logging.debug(f"Added node for Secondary BBMD Connection: {bbmd_node_name}")
                    for device_id in current_ip_device_ids:
                        links["Objects"][device_id][bbmd_node_name] = {}
                        links["Objects"][device_id][bbmd_node_name]["count"] = 1
                        links["Objects"][device_id][bbmd_node_name]["port"] = bbmd_value.get("port", 0)
                        links["Objects"][device_id][bbmd_node_name]["type"] = bbmd_value.get("type", "")
                        links["Objects"][device_id][bbmd_node_name]["ip-address"] = bbmd_ip_address
                        logging.debug(f"Linked Secondary BBMD Connection: {bbmd_node_name} to device_id: {device_id}")

        # Process Email Server Connections
        if "Email Server Connections" in content:
            email_server_data = content.get("Email Server Connections", {})           
            for email_server_key, email_server_value in email_server_data.items():
                email_server_node_name = email_server_value.get("key", "")
                if email_server_value and email_server_value != "error":
                    nodes[email_server_node_name] = {
                        "description": "Email Server Connection",
                        "model-name": "email_server",
                        "node-type": "email_remote",
                    }
                    logging.debug(f"Added node for Email Server Connection: {email_server_node_name}")
                    
                    for device_id in current_ip_device_ids:
                        links["Objects"][device_id][email_server_node_name] = {}
                        links["Objects"][device_id][email_server_node_name]["count"] = 1
                        links["Objects"][device_id][email_server_node_name]["Enabled"] = str(email_server_value.get("enabled", False)).title()
                        links["Objects"][device_id][email_server_node_name]["Hostname"] = email_server_value.get("hostname", "")
                        logging.debug(f"Linked Email Server Connection: {email_server_node_name} to device_id: {device_id}")

        # Calculate cumulative counts
        for local_device_id, devices in links["Network Values"].items():
            total_count = sum(
                device.get("count", 0) 
                for key, device in devices.items() 
                if key != "count"
            )
            links["Network Values"][local_device_id]["count"] = total_count
            logging.debug(f"Set total_count for Network Values of device_id: {local_device_id} to {total_count}")

    # Assign the structured links and nodes back to data
    data["Links"] = links
    data["Nodes"] = nodes
    logging.debug("Finished creating links and nodes.")
    return data

def count_object_names(obj):
    count = 0
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "object-name":
                count += 1
            else:
                count += count_object_names(value)
    return count

def calculate_cumulative_counts(data):
    def recursive_count(obj):
        if isinstance(obj, dict):
            total_count = 0
            for key, value in obj.items():
                if key == "count" and isinstance(value, int):
                    total_count += value
                else:
                    total_count += recursive_count(value)
            return total_count
        return 0
    for section in ["Objects", "Network Values"]:
        if section in data["Links"]:
            for key, value in data["Links"][section].items():
                if isinstance(value, dict):
                    value["count"] = recursive_count(value)
    return data

def reorganize_data(data):
    for ip, content in data.items():
        if "Local BACNet Data" in content:
            for local_id, local_data in content.pop("Local BACNet Data").items():
                local_data["node-type"] = "bacnet_local"
                local_data["ip-address"] = ip
                if local_id in data["Nodes"]:
                    if data["Nodes"][local_id]["node-type"] != "bacnet_local":
                        data["Nodes"][local_id]["node-type"] = "bacnet_local"
                    if "ip-address" not in data["Nodes"][local_id]:
                        data["Nodes"][local_id]["ip-address"] = ip
                else:
                    data["Nodes"][local_id] = local_data
        if "Remote BACnet Data" in content:
            for remote_id, remote_data in content.pop("Remote BACnet Data").items():
                remote_data["node-type"] = "bacnet_remote"
                if remote_id in data["Nodes"]:
                    if data["Nodes"][remote_id]["node-type"] != "bacnet_local":
                        data["Nodes"][remote_id]["node-type"] = "bacnet_remote"
                    if "ip-address" not in data["Nodes"][remote_id]:
                        data["Nodes"][remote_id]["ip-address"] = ip
                else:
                    data["Nodes"][remote_id] = {k: v for k, v in remote_data.items() if k != "objects"}
    return data

async def fetch_all_data(device_ip_addresses, device_username, device_password):
    print(f"Fetching data for IP addresses: {device_ip_addresses}")  
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_device_data(session, ip, device_username, device_password) for ip in device_ip_addresses]
        results = await asyncio.gather(*tasks)
        all_data = {}
        for result in results:
            if result is not None:
                all_data.update(result)
        keys_to_remove = {"4194303", "4194304"}  
        cleaned_data = {ip: remove_entries(data, keys_to_remove) for ip, data in all_data.items()}
        data_with_links = create_links(cleaned_data)
        reorganized_data = reorganize_data(data_with_links)
        for ip, content in reorganized_data.items():
            if "Local GFX Network Values" in content:
                del content["Local GFX Network Values"]
            if "Remote BACnet Data" in content:
                del content["Remote BACnet Data"]
            if "Remote Modbus Data" in content:
                del content["Remote Modbus Data"]
        substrings_to_remove = ["network-policy", "connection-status", "status"]
        for node_id, node_data in reorganized_data["Nodes"].items():
            reorganized_data["Nodes"][node_id] = remove_entries(node_data, set(), substrings_to_remove)
        for ip in list(reorganized_data.keys()):
            if ip in device_ip_addresses:
                del reorganized_data[ip]
        final_data = calculate_cumulative_counts(reorganized_data)     
        return final_data

async def periodic_fetch():
    global all_network_values_global, device_ip_addresses, device_username, device_password
    while True:
        try:
            print("Periodic fetch task started")
            await asyncio.sleep(30)  # Wait for 30 seconds
            all_network_values_global = await fetch_all_data(device_ip_addresses, device_username, device_password)
            print("Periodic fetch task completed")
        except Exception as e:
            print(f"Error in periodic fetch task: {str(e)}")

def run_periodic_fetch():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(periodic_fetch())

@app.route('/api/data', methods=['GET'])
async def get_data():
    global initial_fetch_completed, all_network_values_global
    if not initial_fetch_completed:
        all_network_values_global = await fetch_all_data()
        initial_fetch_completed = True
    return jsonify(all_network_values_global)

@app.route('/api/data', methods=['POST'])
async def update_data():
    global initial_fetch_completed, all_network_values_global, device_username, device_password, device_ip_addresses
    ip_input = request.json.get('ip_addresses', '')
    device_ip_addresses = parse_ip_addresses(ip_input)
    device_username = request.json.get('username', '')
    device_password = request.json.get('password', '')
    print(f"Received IP addresses: {device_ip_addresses}")
    print(f"Received username: {device_username}")
    print(f"Received password: {device_password}")
    if not initial_fetch_completed or device_ip_addresses != all_network_values_global.get('ip_addresses', []):
        all_network_values_global = await fetch_all_data(device_ip_addresses, device_username, device_password)
        all_network_values_global['ip_addresses'] = device_ip_addresses
        initial_fetch_completed = True
    return jsonify(all_network_values_global)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico')

@app.route('/')
def index():
    return render_template('index_v5.html')

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    all_network_values_global = loop.run_until_complete(fetch_all_data(device_ip_addresses, device_username, device_password))
    initial_fetch_completed = True
    thread = threading.Thread(target=run_periodic_fetch)
    thread.daemon = True
    thread.start()
    app.run(debug=False)
