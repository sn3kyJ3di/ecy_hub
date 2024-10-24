import os
import base64
import aiohttp
import asyncio
import requests
import logging
import threading

from aiohttp import ClientTimeout
from flask import Flask, jsonify, render_template, send_from_directory, request
from typing import Dict, Any, Set
from urllib.parse import urlparse

app = Flask(__name__)

device_username = ""
device_password = ""

device_ip_addresses = []
device_cookies = {}
cache = {}
initial_fetch_completed = False
all_network_values_global = {}
device_ip_addresses = set()  # Active IPs as a set
failed_ip_addresses = set()  # Failed IPs as a set

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.DEBUG)

def parse_uri(uri: str) -> Dict[str, Any]:
    """
    Parses a WebSocket URI to extract IP and port.

    Args:
        uri (str): The WebSocket URI (e.g., "wss://167.235.201.6:1443/hub")

    Returns:
        Dict[str, Any]: A dictionary with 'ip' and 'port' keys.
     """
    parsed = urlparse(uri)
    ip = parsed.hostname
    port = parsed.port
    return {"ip": ip, "port": port} if ip and port else {"ip": None, "port": None}

def merge_non_null(original_dict, new_dict, parent_key=''):
    """
    Recursively merge two dictionaries, updating only the keys where the new value is not null or empty.
    Logs the merging process for debugging purposes.

    Args:
        original_dict (dict): The dictionary to be updated.
        new_dict (dict): The dictionary with new data.
        parent_key (str): The hierarchical key path (used for logging).
    """
    for key, value in new_dict.items():
        full_key = f"{parent_key}.{key}" if parent_key else key
        if isinstance(value, dict) and key in original_dict and isinstance(original_dict[key], dict):
            logging.debug(f"Merging nested dictionary for key '{full_key}'")
            merge_non_null(original_dict[key], value, parent_key=full_key)
        elif value is not None and value != "" or value != 'null':
            if key in original_dict:
                logging.debug(f"Updating key '{full_key}': '{original_dict[key]}' -> '{value}'")
            else:
                logging.debug(f"Adding new key '{full_key}' with value '{value}'")
            original_dict[key] = value
        else:
            logging.debug(f"Skipping key '{full_key}' with null or empty value")

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
                "url": "/api/rest/v2/services/bacnet/remote/devices?$select=*($select=vendor-name&$select=address&$select=objects($select=*($select=*($select=object-name)))&$select=local-name&$select=model-name&$select=description&$select=location&$select=connection-status)"
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
            },
                        {
                "id": "BACNet/SC",
                "method": "GET",
                "url": "/api/rest/v2/services/bacnet/communication/network/ports/secure-connect?$select=enabled&$select=network-number&$select=hub-function&$select=hub-connector&$select=description&$select=node-switch"
            }
        ]
    }

    timeout = ClientTimeout(total=5)
    
    try:
        async with session.post(url, headers=headers, json=body, ssl=False, timeout=timeout) as response:
            if response.status == 200:
                data = await response.json()
                structured_data = {}
                for response_item in data.get("responses", []):
                    response_id = response_item.get("id")
                    response_body = response_item.get("body")
                    structured_data[response_id] = response_body
                return {ip: structured_data}
            else:
                logging.error(f"Client error fetching data from {ip}: HTTP {response.status}")
                return {"ip": ip, "status": "error", "message": f"HTTP {response.status}"}
    except asyncio.TimeoutError:
        logging.error(f"Timeout error fetching data from {ip}")
        return {"ip": ip, "status": "timeout", "message": "Request timed out"}
    except aiohttp.ClientError as e:
        logging.error(f"Unexpected error fetching data from {ip}: {e}")
        return {"ip": ip, "status": "error", "message": str(e)}

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

                # Ensure the device_id exists in links
                if device_id not in links["Objects"]:
                    links["Objects"][device_id] = {}
                if device_id not in links["Network Values"]:
                    links["Network Values"][device_id] = {}

                # Prepare new node data
                new_node_data = {
                    "description": device_data.get("description", ""),
                    "local-name": device_data.get("object-name", ""),
                    "location": device_data.get("location", ""),
                    "model-name": device_data.get("model-name", ""),
                    "ip-address": ip,
                    "node-type": "bacnet_local"
                }

                # Update nodes dictionary
                if device_id not in nodes:
                    nodes[device_id] = new_node_data
                    logging.debug(f"Added new node for device_id: {device_id}")
                else:
                    merge_non_null(nodes[device_id], new_node_data)
                    logging.debug(f"Updated node for device_id: {device_id}")

                # Process Remote BACnet Data
                if "Remote BACnet Data" in content:
                    for remote_id, remote_data in content["Remote BACnet Data"].items():
                        if remote_id in keys_to_ignore:
                            logging.debug(f"Ignoring remote_id: {remote_id}")
                            continue

                        if remote_id not in links["Objects"][device_id]:
                            links["Objects"][device_id][remote_id] = {}

                        if remote_id == device_id:
                            # Merge remote_data into links["Objects"][device_id][remote_id]
                            merge_non_null(links["Objects"][device_id][remote_id], remote_data)
                            logging.debug(f"Merged remote_data into links['Objects'][{device_id}][{remote_id}]")
                        else:
                            if "objects" not in links["Objects"][device_id][remote_id]:
                                links["Objects"][device_id][remote_id]["objects"] = {}
                            merge_non_null(links["Objects"][device_id][remote_id]["objects"], remote_data.get("objects", {}))
                            logging.debug(f"Merged objects for remote_id: {remote_id} into links['Objects'][{device_id}][{remote_id}]['objects']")

                        # Update count and connection status
                        count = count_object_names(links["Objects"][device_id][remote_id].get("objects", {}))
                        links["Objects"][device_id][remote_id]["count"] = count
                        logging.debug(f"Set count for links['Objects'][{device_id}][{remote_id}] to {count}")

                        connection_status = str(remote_data.get("connection-status", {})).title()
                        if "Connection-Status" not in links["Objects"][device_id][remote_id] or not links["Objects"][device_id][remote_id]["Connection-Status"]:
                            links["Objects"][device_id][remote_id]["Connection-Status"] = connection_status
                            logging.debug(f"Set Connection-Status for links['Objects'][{device_id}][{remote_id}] to '{connection_status}'")
                        else:
                            logging.debug(f"Existing Connection-Status for links['Objects'][{device_id}][{remote_id}] is '{links['Objects'][device_id][remote_id]['Connection-Status']}'")

                        # Set node-type
                        links["Objects"][device_id][remote_id]["node-type"] = "bacnet_remote"
                        logging.debug(f"Set node-type for links['Objects'][{device_id}][{remote_id}] to 'bacnet_remote'")

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
                            # Determine object name
                            object_name = "N/A"
                            if (local_device_id in links["Objects"] and
                                remote_device_id in links["Objects"][local_device_id] and
                                "objects" in links["Objects"][local_device_id][remote_device_id] and
                                object_type in links["Objects"][local_device_id][remote_device_id]["objects"] and
                                object_id in links["Objects"][local_device_id][remote_device_id]["objects"][object_type]):
                                object_name = links["Objects"][local_device_id][remote_device_id]["objects"][object_type][object_id].get("object-name", "")
                            links["Network Values"][local_device_id][remote_device_id]["objects"][object_type][object_id] = {"object-name": object_name}
                            logging.debug(f"Added object '{object_id}' of type '{object_type}' with name '{object_name}' to links['Network Values'][{local_device_id}][{remote_device_id}]['objects']")

                        # Update count
                        count = count_object_names(links["Network Values"][local_device_id][remote_device_id].get("objects", {}))
                        links["Network Values"][local_device_id][remote_device_id]["count"] = count
                        logging.debug(f"Set count for links['Network Values'][{local_device_id}][{remote_device_id}] to {count}")

                        # Update connection status if available
                        if remote_device_id in content.get("Remote BACnet Data", {}):
                            remote_data = content["Remote BACnet Data"][remote_device_id]
                            connection_status = remote_data.get("connection-status", {})
                            if "Connection-Status" not in links["Network Values"][local_device_id][remote_device_id] or not links["Network Values"][local_device_id][remote_device_id]["Connection-Status"]:
                                links["Network Values"][local_device_id][remote_device_id]["Connection-Status"] = connection_status
                                logging.debug(f"Set Connection-Status for links['Network Values'][{local_device_id}][{remote_device_id}] to '{connection_status}'")
                            else:
                                logging.debug(f"Existing Connection-Status for links['Network Values'][{local_device_id}][{remote_device_id}] is '{links['Network Values'][local_device_id][remote_device_id]['Connection-Status']}'")

        # Process Remote Modbus Data
        if "Remote Modbus Data" in content:
            for modbus_key, modbus_value in content["Remote Modbus Data"].items():
                if modbus_value != "error" and modbus_value:
                    new_node_data = {
                        "ip-address": modbus_value.get("address", {}).get("ip", ""),
                        "node-type": "modbus_remote",
                        "status": modbus_value.get("status", "")
                    }
                    if modbus_key not in nodes:
                        nodes[modbus_key] = new_node_data
                        logging.debug(f"Added new node for modbus_key: {modbus_key}")
                    else:
                        merge_non_null(nodes[modbus_key], new_node_data)
                        logging.debug(f"Updated node for modbus_key: {modbus_key}")

                    if not current_ip_device_ids:
                        logging.warning(f"No local device found for IP {ip} while processing Remote Modbus Data.")
                        continue
                    local_device_id = next(iter(current_ip_device_ids))  # Assuming one local device per IP
                    if local_device_id not in links["Objects"]:
                        links["Objects"][local_device_id] = {}
                    if modbus_key not in links["Objects"][local_device_id]:
                        links["Objects"][local_device_id][modbus_key] = {}
                        logging.debug(f"Initialized links['Objects'][{local_device_id}][{modbus_key}]")
                    
                    # Clean modbus_value by removing 'address' and 'ip'
                    modbus_value_cleaned = {k: v for k, v in modbus_value.items() if k not in {"address", "ip"}}
                    if "points" in modbus_value_cleaned:
                        for point_key, point_value in modbus_value_cleaned["points"].items():
                            if "key" in point_value:
                                point_value["object-name"] = point_value.pop("key")

                    # Merge cleaned modbus data into links
                    merge_non_null(links["Objects"][local_device_id][modbus_key], modbus_value_cleaned)
                    logging.debug(f"Merged modbus_value_cleaned into links['Objects'][{local_device_id}][{modbus_key}]")

                    # Update count and connection status
                    count = len(modbus_value_cleaned.get("points", {}))
                    links["Objects"][local_device_id][modbus_key]["count"] = count
                    logging.debug(f"Set count for links['Objects'][{local_device_id}][{modbus_key}] to {count}")

                    connection_status = str(modbus_value.get("status", "")).title()
                    if "Connection-Status" not in links["Objects"][local_device_id][modbus_key] or not links["Objects"][local_device_id][modbus_key]["Connection-Status"]:
                        links["Objects"][local_device_id][modbus_key]["Connection-Status"] = connection_status
                        logging.debug(f"Set Connection-Status for links['Objects'][{local_device_id}][{modbus_key}] to '{connection_status}'")
                    else:
                        logging.debug(f"Existing Connection-Status for links['Objects'][{local_device_id}][{modbus_key}] is '{links['Objects'][local_device_id][modbus_key]['Connection-Status']}'")

                    # Set node-type
                    links["Objects"][local_device_id][modbus_key]["node-type"] = "modbus_remote"
                    logging.debug(f"Set node-type for links['Objects'][{local_device_id}][{modbus_key}] to 'modbus_remote'")

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
                            logging.debug(f"Initialized links['Network Values'][{local_device_id}][{device_name}]")
                        links["Network Values"][local_device_id][device_name]["count"] += 1
                        logging.debug(f"Incremented count for device_name: {device_name} in links['Network Values'][{local_device_id}]")

                        if device_name in content.get("Remote Modbus Data", {}):
                            remote_data = content["Remote Modbus Data"][device_name]
                            connection_status = remote_data.get("status", {})
                            if "Connection-Status" not in links["Network Values"][local_device_id][device_name] or not links["Network Values"][local_device_id][device_name]["Connection-Status"]:
                                links["Network Values"][local_device_id][device_name]["Connection-Status"] = connection_status
                                logging.debug(f"Set Connection-Status for device_name: {device_name} in links['Network Values'][{local_device_id}] to '{connection_status}'")
                            else:
                                logging.debug(f"Existing Connection-Status for device_name: {device_name} in links['Network Values'][{local_device_id}] is '{links['Network Values'][local_device_id][device_name]['Connection-Status']}'")

        # Process IOT Connections
        if "IOT Connections" in content:
            for iot_key, iot_value in content["IOT Connections"].items():
                if iot_value != "error" and iot_value:
                    new_node_data = {
                        "description": "IOT Connection",
                        "model-name": "iot_hub",
                        "node-type": "iot_remote",
                        "connection-status": iot_value.get("status", "")
                    }
                    if iot_key not in nodes:
                        nodes[iot_key] = new_node_data
                        logging.debug(f"Added new node for iot_key: {iot_key}")
                    else:
                        merge_non_null(nodes[iot_key], new_node_data)
                        logging.debug(f"Updated node for iot_key: {iot_key}")

                    for device_id in current_ip_device_ids:
                        if device_id not in links["Objects"]:
                            links["Objects"][device_id] = {}
                        if iot_key not in links["Objects"][device_id]:
                            links["Objects"][device_id][iot_key] = {}
                            logging.debug(f"Initialized links['Objects'][{device_id}][{iot_key}]")
                        links["Objects"][device_id][iot_key]["count"] = 1
                        connection_status = "Online" if iot_value.get("status") == "Connected" else "Offline"
                        if "Connection-Status" not in links["Objects"][device_id][iot_key] or not links["Objects"][device_id][iot_key]["Connection-Status"]:
                            links["Objects"][device_id][iot_key]["Connection-Status"] = connection_status
                            logging.debug(f"Set Connection-Status for links['Objects'][{device_id}][{iot_key}] to '{connection_status}'")
                        else:
                            logging.debug(f"Existing Connection-Status for links['Objects'][{device_id}][{iot_key}] is '{links['Objects'][device_id][iot_key]['Connection-Status']}'")

        # Process Remote Tunnel Connections
        if "Remote Tunnel Connections" in content:
            remote_tunnel_data = content.get("Remote Tunnel Connections", {})
            for rmt_key, rmt_value in remote_tunnel_data.items():
                if rmt_value != "error" and rmt_value:
                    new_node_data = {
                        "description": "Remote Tunnel Connection",
                        "model-name": "rmt_tunnel",
                        "node-type": "rmt_remote",
                        "connection-status": "Online" if rmt_value.get("enabled") else "Offline"
                    }
                    if rmt_key not in nodes:
                        nodes[rmt_key] = new_node_data
                        logging.debug(f"Added new node for remote tunnel: {rmt_key}")
                    else:
                        merge_non_null(nodes[rmt_key], new_node_data)
                        logging.debug(f"Updated node for remote tunnel: {rmt_key}")

                    for device_id in current_ip_device_ids:
                        if device_id not in links["Objects"]:
                            links["Objects"][device_id] = {}
                        if rmt_key not in links["Objects"][device_id]:
                            links["Objects"][device_id][rmt_key] = {}
                            logging.debug(f"Initialized links['Objects'][{device_id}][{rmt_key}]")
                        
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

                        # Merge tunnels
                        existing_tunnels = links["Objects"][device_id][rmt_key].get("Tunnels", [])
                        updated_tunnels = existing_tunnels + tunnels
                        links["Objects"][device_id][rmt_key]["Tunnels"] = updated_tunnels
                        logging.debug(f"Merged tunnels for links['Objects'][{device_id}][{rmt_key}]")

                        # Update count and connection status
                        count = len(updated_tunnels)
                        links["Objects"][device_id][rmt_key]["count"] = count
                        logging.debug(f"Set count for links['Objects'][{device_id}][{rmt_key}] to {count}")

                        connection_status = "Online" if rmt_value.get("enabled") else "Offline"
                        if "Connection-Status" not in links["Objects"][device_id][rmt_key] or not links["Objects"][device_id][rmt_key]["Connection-Status"]:
                            links["Objects"][device_id][rmt_key]["Connection-Status"] = connection_status
                            logging.debug(f"Set Connection-Status for links['Objects'][{device_id}][{rmt_key}] to '{connection_status}'")
                        else:
                            logging.debug(f"Existing Connection-Status for links['Objects'][{device_id}][{rmt_key}] is '{links['Objects'][device_id][rmt_key]['Connection-Status']}'")

        # Process MQTT Broker Connections
        if "MQTT Broker Connections" in content:
            mqtt_data = content.get("MQTT Broker Connections", {})
            for mqtt_key, mqtt_value in mqtt_data.items():
                if mqtt_value != "error" and mqtt_value:
                    new_node_data = {
                        "description": "MQTT Broker",
                        "model-name": "mqtt_broker",
                        "node-type": "mqtt_remote",
                        "connection-status": "Online" if mqtt_value.get("enabled") else "Offline"
                    }
                    if mqtt_key not in nodes:
                        nodes[mqtt_key] = new_node_data
                        logging.debug(f"Added new node for MQTT Broker: {mqtt_key}")
                    else:
                        merge_non_null(nodes[mqtt_key], new_node_data)
                        logging.debug(f"Updated node for MQTT Broker: {mqtt_key}")

                    for device_id in current_ip_device_ids:
                        if device_id not in links["Objects"]:
                            links["Objects"][device_id] = {}
                        if mqtt_key not in links["Objects"][device_id]:
                            links["Objects"][device_id][mqtt_key] = {}
                            logging.debug(f"Initialized links['Objects'][{device_id}][{mqtt_key}]")
                        links["Objects"][device_id][mqtt_key]["count"] = 1
                        connection_status = "Online" if mqtt_value.get("enabled") else "Offline"
                        if "Connection-Status" not in links["Objects"][device_id][mqtt_key] or not links["Objects"][device_id][mqtt_key]["Connection-Status"]:
                            links["Objects"][device_id][mqtt_key]["Connection-Status"] = connection_status
                            logging.debug(f"Set Connection-Status for links['Objects'][{device_id}][{mqtt_key}] to '{connection_status}'")
                        else:
                            logging.debug(f"Existing Connection-Status for links['Objects'][{device_id}][{mqtt_key}] is '{links['Objects'][device_id][mqtt_key]['Connection-Status']}'")

        # Process Weather Connections
        if "Weather Connections" in content:
            weather_data = content.get("Weather Connections", {})
            for weather_key, weather_value in weather_data.items():
                if weather_value != "error" and weather_value:
                    provider_name = weather_value.get("provider", "")
                    provider_name = provider_name.title() if provider_name.lower() == "accuweather" else provider_name
                    new_node_data = {
                        "description": "Weather Connection",
                        "model-name": "weather_server",
                        "node-type": "weather_remote",
                        "provider": provider_name,
                        "status": weather_value.get("report", {}).get("status", 0),
                    }
                    if provider_name not in nodes:
                        nodes[provider_name] = new_node_data
                        logging.debug(f"Added new node for Weather Connection: {provider_name}")
                    else:
                        merge_non_null(nodes[provider_name], new_node_data)
                        logging.debug(f"Updated node for Weather Connection: {provider_name}")

                    for device_id in current_ip_device_ids:
                        if device_id not in links["Objects"]:
                            links["Objects"][device_id] = {}
                        if provider_name not in links["Objects"][device_id]:
                            links["Objects"][device_id][provider_name] = {}
                            logging.debug(f"Initialized links['Objects'][{device_id}][{provider_name}]")
                        links["Objects"][device_id][provider_name]["count"] = 1
                        connection_status = "Online" if weather_value.get("report", {}).get("status-message") == "OK" else "Offline"
                        links["Objects"][device_id][provider_name]["Connection-Status"] = connection_status
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

                # Add or update Internet Connection node
                new_node_data = {
                    "description": "Internet Connection",
                    "model-name": "internet_server",
                    "node-type": "internet_remote",
                    "connection-status": "Online" if internet_data.get("connected-to-internet") else "Offline",
                }
                if internet_node_name not in nodes:
                    nodes[internet_node_name] = new_node_data
                    logging.debug(f"Added new node for Internet Connection: {internet_node_name}")
                else:
                    merge_non_null(nodes[internet_node_name], new_node_data)
                    logging.debug(f"Updated node for Internet Connection: {internet_node_name}")

                if local_device_id not in links["Objects"]:
                    links["Objects"][local_device_id] = {}
                if internet_node_name not in links["Objects"][local_device_id]:
                    links["Objects"][local_device_id][internet_node_name] = {}
                    logging.debug(f"Initialized links['Objects'][{local_device_id}][{internet_node_name}]")
                links["Objects"][local_device_id][internet_node_name]["count"] = 1
                connection_status = "Online" if internet_data.get("connected-to-internet") else "Offline"
                links["Objects"][local_device_id][internet_node_name]["Connection-Status"] = connection_status
                links["Objects"][local_device_id][internet_node_name]["Public-Ip"] = internet_data.get("public-ip", "")
                logging.debug(f"Linked Internet Connection to device_id: {local_device_id}")

                # Add or update NTP Connection node
                ntp_data = internet_ntp_data.get("time", {}).get("ntp", {})
                ntp_node_name = "NTP Connection"

                new_node_data = {
                    "description": "TimeSync Server",
                    "model-name": "time_server",
                    "node-type": "ntp_remote",
                    "connection-status": "Online" if ntp_data.get("synchronized") else "Offline",
                }
                if ntp_node_name not in nodes:
                    nodes[ntp_node_name] = new_node_data
                    logging.debug(f"Added new node for NTP Connection: {ntp_node_name}")
                else:
                    merge_non_null(nodes[ntp_node_name], new_node_data)
                    logging.debug(f"Updated node for NTP Connection: {ntp_node_name}")

                if ntp_node_name not in links["Objects"][local_device_id]:
                    links["Objects"][local_device_id][ntp_node_name] = {}
                    logging.debug(f"Initialized links['Objects'][{local_device_id}][{ntp_node_name}]")
                links["Objects"][local_device_id][ntp_node_name]["count"] = 1
                connection_status = "Online" if ntp_data.get("synchronized") else "Offline"
                links["Objects"][local_device_id][ntp_node_name]["Connection-Status"] = connection_status
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
                        logging.debug(f"Initialized links['Objects'][{local_device_id}][{bbmd_device_id}]")
                    links["Objects"][local_device_id][bbmd_device_id]["bbmd_primary"] = {
                        "port": bbmd_value.get("port", 0),
                        "type": bbmd_value.get("type", "")
                    }
                    links["Objects"][local_device_id][bbmd_device_id]["count"] = links["Objects"][local_device_id][bbmd_device_id].get("count", 0) + 1
                    logging.debug(f"Linked BBMD Primary: {bbmd_key} to device_id: {local_device_id} and bbmd_device_id: {bbmd_device_id}")
                else:
                    bbmd_node_name = f"Primary BBMD-{bbmd_key}"
                    new_node_data = {
                        "description": "Primary BBMD Connection",
                        "model-name": "bbmd",
                        "node-type": "bbmd_primary",
                    }
                    if bbmd_node_name not in nodes:
                        nodes[bbmd_node_name] = new_node_data
                        logging.debug(f"Added new node for Primary BBMD Connection: {bbmd_node_name}")
                    else:
                        merge_non_null(nodes[bbmd_node_name], new_node_data)
                        logging.debug(f"Updated node for Primary BBMD Connection: {bbmd_node_name}")

                    for device_id in current_ip_device_ids:
                        if device_id not in links["Objects"]:
                            links["Objects"][device_id] = {}
                        if bbmd_node_name not in links["Objects"][device_id]:
                            links["Objects"][device_id][bbmd_node_name] = {}
                            logging.debug(f"Initialized links['Objects'][{device_id}][{bbmd_node_name}]")
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
                        logging.debug(f"Initialized links['Objects'][{local_device_id}][{bbmd_device_id}]")
                    links["Objects"][local_device_id][bbmd_device_id]["bbmd_secondary"] = {
                        "port": bbmd_value.get("port", 0),
                        "type": bbmd_value.get("type", "")
                    }
                    links["Objects"][local_device_id][bbmd_device_id]["count"] = links["Objects"][local_device_id][bbmd_device_id].get("count", 0) + 1
                    logging.debug(f"Linked BBMD Secondary: {bbmd_key} to device_id: {local_device_id} and bbmd_device_id: {bbmd_device_id}")
                else:
                    bbmd_node_name = f"Secondary BBMD Connection {bbmd_key}"
                    new_node_data = {
                        "description": "Secondary BBMD Connection",
                        "model-name": "bbmd",
                        "node-type": "bbmd_secondary",
                    }
                    if bbmd_node_name not in nodes:
                        nodes[bbmd_node_name] = new_node_data
                        logging.debug(f"Added new node for Secondary BBMD Connection: {bbmd_node_name}")
                    else:
                        merge_non_null(nodes[bbmd_node_name], new_node_data)
                        logging.debug(f"Updated node for Secondary BBMD Connection: {bbmd_node_name}")

                    for device_id in current_ip_device_ids:
                        if device_id not in links["Objects"]:
                            links["Objects"][device_id] = {}
                        if bbmd_node_name not in links["Objects"][device_id]:
                            links["Objects"][device_id][bbmd_node_name] = {}
                            logging.debug(f"Initialized links['Objects'][{device_id}][{bbmd_node_name}]")
                        links["Objects"][device_id][bbmd_node_name]["count"] = 1
                        links["Objects"][device_id][bbmd_node_name]["port"] = bbmd_value.get("port", 0)
                        links["Objects"][device_id][bbmd_node_name]["type"] = bbmd_value.get("type", "")
                        links["Objects"][device_id][bbmd_node_name]["ip-address"] = bbmd_ip_address
                        links["Objects"][device_id][bbmd_node_name]["Enabled"] = str(bbmd_data.get("secondary", {}).get("enabled", {})).title()
                        logging.debug(f"Linked Secondary BBMD Connection: {bbmd_node_name} to device_id: {device_id}")

            # Initialize BACNetSC if not already present
       
        if "BACNet/SC" in content:
            local_device_id = next(iter(current_ip_device_ids))  # Assuming one local device per IP
            nodes.setdefault(local_device_id, {}).setdefault("BACNetSC", {})
            bacnet_sc_data = content.get("BACNet/SC", {})

            # BACNet/SC Enabled Status
            bacnet_sc_enabled = bacnet_sc_data.get("enabled", False)
            nodes[local_device_id]["BACNetSC"]["enabled"] = bacnet_sc_enabled

            if not bacnet_sc_enabled:
                logging.debug(f"BACNet/SC disabled for device {local_device_id}, skipping further processing.")
                continue  # BACNet/SC is disabled; skip further processing

            # Assign Network Number and Description
            network_number = bacnet_sc_data.get("network-number")
            network_description = bacnet_sc_data.get("description")
            nodes[local_device_id]["BACNetSC"]["network_number"] = network_number
            nodes[local_device_id]["BACNetSC"]["network_description"] = network_description

            # ----------------------------
            # Process Hub Connector
            # ----------------------------
            hub_connector = bacnet_sc_data.get("hub-connector", {})
            hub_connector_enabled = hub_connector.get("enabled", False)
            nodes[local_device_id]["BACNetSC"].setdefault("hub-connector", {})["enabled"] = hub_connector_enabled

            if hub_connector_enabled:
                # Assign Hub Connector State
                hub_connector_state = hub_connector.get("state", "")
                nodes[local_device_id]["BACNetSC"]["hub-connector"]["state"] = hub_connector_state

                # Parse and Assign Primary Hub
                primary_uri = hub_connector.get("primary-uri", "")
                primary_hub = parse_uri(primary_uri) if primary_uri else {"ip": None, "port": None}
                primary_hub["state"] = hub_connector.get("primary-state", "")
                nodes[local_device_id]["BACNetSC"]["hub-connector"]["primary_hub"] = primary_hub

                # Parse and Assign Failover Hub
                failover_uri = hub_connector.get("failover-uri", "")
                failover_hub = parse_uri(failover_uri) if failover_uri else {"ip": None, "port": None}
                failover_hub["state"] = hub_connector.get("failover-state", "")
                nodes[local_device_id]["BACNetSC"]["hub-connector"]["failover_hub"] = failover_hub
            else:
                # If hub_connector is not enabled, assign default values
                nodes[local_device_id]["BACNetSC"]["hub-connector"]["state"] = ""
                nodes[local_device_id]["BACNetSC"]["hub-connector"]["primary_hub"] = {"ip": None, "port": None, "state": ""}
                nodes[local_device_id]["BACNetSC"]["hub-connector"]["failover_hub"] = {"ip": None, "port": None, "state": ""}

            # ----------------------------
            # Process Node Switch
            # ----------------------------
            node_switch = bacnet_sc_data.get("node-switch", {})
            node_switch_accept_enabled = node_switch.get("accept-enabled", False)
            
            # Ensure BACNetSC and node-switch keys are present before accessing them
            nodes.setdefault(local_device_id, {}).setdefault("BACNetSC", {}).setdefault("node-switch", {})["accept_enabled"] = node_switch_accept_enabled

            if node_switch_accept_enabled:
            # Assign Node Switch State
                node_switch_state = node_switch.get("state", "")
                nodes[local_device_id]["BACNetSC"]["node-switch"]["state"] = node_switch_state

                # Ensure "outgoing" key exists before updating it
                nodes[local_device_id]["BACNetSC"]["node-switch"].setdefault("outgoing", {})
                nodes[local_device_id]["BACNetSC"]["node-switch"]["outgoing"]["enabled"] = node_switch.get("initiate-enabled", False)

                if nodes[local_device_id]["BACNetSC"]["node-switch"]["outgoing"]["enabled"]:
                    # Parse and Assign Outgoing Connectors
                    connectors = node_switch.get("connectors", {})
                    processed_connectors = {}
                    for key, connector in connectors.items():
                        connector_ip_port = parse_uri(connector.get("uri", ""))
                        connector_state = connector.get("state", "")
                        connector_connection_state = connector.get("connection-state", "")
                        processed_connectors[key] = {
                            "ip": connector_ip_port.get("ip"),
                            "port": connector_ip_port.get("port"),
                            "state": connector_state,
                            "connection_state": connector_connection_state
                        }
                    nodes[local_device_id]["BACNetSC"]["node-switch"]["outgoing"]["connections"] = processed_connectors
                else:
                    # If outgoing is not enabled, assign default values
                    nodes[local_device_id]["BACNetSC"]["node-switch"]["outgoing"]["connections"] = {}

                # Process Incoming Connections
                incoming_enabled = node_switch_accept_enabled
                nodes[local_device_id]["BACNetSC"]["node-switch"].setdefault("incoming", {})["enabled"] = incoming_enabled

                if incoming_enabled:
                    # Parse and Assign Incoming Connections
                    connections = node_switch.get("connections", {})
                    processed_node_connections = {}
                    for key, conn in connections.items():
                        conn_ip_port = parse_uri(conn.get("uri", ""))
                        conn_state = conn.get("state", "")
                        conn_connection_state = conn.get("connection-state", "")
                        processed_node_connections[key] = {
                            "ip": conn_ip_port.get("ip"),
                            "port": conn_ip_port.get("port"),
                            "state": conn_state,
                            "connection_state": conn_connection_state
                        }
                    nodes[local_device_id]["BACNetSC"]["node-switch"]["incoming"]["connections"] = processed_node_connections
                else:
                    # If incoming is not enabled, assign default values
                    nodes[local_device_id]["BACNetSC"]["node-switch"]["incoming"]["connections"] = {}

                # Assign Other Node Switch Attributes
                nodes[local_device_id]["BACNetSC"]["node-switch"]["initiate_enabled"] = node_switch.get("initiate-enabled", False)
                nodes[local_device_id]["BACNetSC"]["node-switch"]["endpoint"] = node_switch.get("endpoint", "")
            else:
                # If node-switch is not enabled, assign default values
                nodes[local_device_id]["BACNetSC"]["node-switch"]["state"] = ""
                nodes[local_device_id]["BACNetSC"]["node-switch"].setdefault("outgoing", {})
                nodes[local_device_id]["BACNetSC"]["node-switch"]["outgoing"]["enabled"] = False
                nodes[local_device_id]["BACNetSC"]["node-switch"]["outgoing"]["connections"] = {}
                nodes[local_device_id]["BACNetSC"]["node-switch"].setdefault("incoming", {})
                nodes[local_device_id]["BACNetSC"]["node-switch"]["incoming"]["enabled"] = False
                nodes[local_device_id]["BACNetSC"]["node-switch"]["incoming"]["connections"] = {}
                nodes[local_device_id]["BACNetSC"]["node-switch"]["initiate_enabled"] = False
                nodes[local_device_id]["BACNetSC"]["node-switch"]["endpoint"] = ""

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

def process_bacnet_sc_links(nodes, links):
    for device_id, device_data in list(nodes.items()):  # Iterate over a copy of the nodes
        bacnet_sc = device_data.get("BACNetSC")
        if bacnet_sc:
            # Check primary hub for IP
            primary_ip = bacnet_sc.get("hub-connector", {}).get("primary_hub", {}).get("ip")
            primary_state = bacnet_sc.get("hub-connector", {}).get("primary_hub", {}).get("state")
            if primary_ip:
                existing_node = find_node_by_ip(nodes, primary_ip)
                if existing_node:
                    # Create the link to the existing node (Primary Hub)
                    create_link_to_existing_node(device_id, primary_ip, "Primary Hub", links, primary_state)
                else:
                    # Create a new node and link to it
                    create_node_for_ip(primary_ip, "bacnetsc_primary", "Primary Hub", nodes)
                    create_link_to_existing_node(device_id, primary_ip, "Primary Hub", links, primary_state)

            # Check failover hub for IP
            failover_ip = bacnet_sc.get("hub-connector", {}).get("failover_hub", {}).get("ip")
            failover_state = bacnet_sc.get("hub-connector", {}).get("failover_hub", {}).get("state")
            if failover_ip:
                existing_node = find_node_by_ip(nodes, failover_ip)
                if existing_node:
                    create_link_to_existing_node(device_id, failover_ip, "Failover Hub", nodes, links, failover_state)
                else:
                    create_node_for_ip(failover_ip, "bacnetsc_failover", "Failover Hub", nodes)

            # Check outgoing connections for IPs
            outgoing_connections = bacnet_sc.get("node-switch", {}).get("outgoing", {}).get("connections", {})
            for conn_name, conn_data in outgoing_connections.items():
                outgoing_ip = conn_data.get("ip")
                outgoing_state = conn_data.get("connection_state")
                if outgoing_ip:
                    existing_node = find_node_by_ip(nodes, outgoing_ip)
                    if existing_node:
                        create_link_to_existing_node(device_id, outgoing_ip, "Outgoing Connection", nodes, links, outgoing_state)
                    else:
                        create_node_for_ip(outgoing_ip, "bacnetsc_direct", "Outgoing Connection", nodes, links)
                       
def find_node_by_ip(nodes, ip_address):
    for node_id, node_data in nodes.items():
        if node_data.get("ip-address") == ip_address:
            return node_id
    return None
                  
def create_node_for_ip(ip_address, node_type, description, nodes):
    """
    Creates a new node for the given IP address if it doesn't already exist.
    The IP address will be used as the node ID.
    """
    if ip_address in nodes:
        # If the node for this IP address already exists, return its ID (the IP address itself)
        return ip_address

    # If the node doesn't exist, create a new node with the IP address as the key
    new_device_id = ip_address  # Use the IP address as the unique ID
    nodes[new_device_id] = {
        "ip-address": ip_address,
        "model-name": node_type,
        "node-type": node_type,
        "description": description,
        "BACNetSC": {
            "enabled": True
        }
    }

    return new_device_id

def create_link(source_id, target_id, connection_name, nodes):
    """
    Create a link between two nodes if it doesn't exist already.
    """
    if "Links" not in nodes:
        nodes["Links"] = {}
    if source_id not in nodes["Links"]:
        nodes["Links"][source_id] = {}
    if target_id not in nodes["Links"][source_id]:
        nodes["Links"][source_id][target_id] = {
            "Connection-Status": "Pending",
            "connection_name": connection_name,
            "node-type": "bacnetsc_connection"
        }

def create_link_to_existing_node(device_id, existing_node_ip, description, links, state):
    # Ensure there's an entry for the device in the Links section's Objects
    if device_id not in links["Objects"]:
        links["Objects"][device_id] = {}

    # Add the existing node as a link under the device's Objects
    links["Objects"][device_id][existing_node_ip] = {
        "Description": description,
        "node-type": "bacnetsc_primary",
        "Connection-Status": state
    }

    # Increment the count of the objects linked to this device
    links["Objects"][device_id]["count"] = len(links["Objects"][device_id]) - 1  # Exclude the count itself
       
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
    logging.info(f"Fetching data for IP addresses: {device_ip_addresses}")
    global failed_ip_addresses
    failed_ip_addresses = set()  # Reset the set at the start of the fetch  
    all_network_values_global["loading"] = True  # Set loading to True

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_device_data(session, ip, device_username, device_password) for ip in device_ip_addresses]
        results = await asyncio.gather(*tasks)

        all_data = {}
        for result in results:
            if isinstance(result, dict) and "status" in result:
                ip = result.get("ip")
                status = result.get("status")
                message = result.get("message")
                if status == "timeout" or status == "error":
                    failed_ip_addresses.add(ip)
                    device_ip_addresses.discard(ip)  # Remove from active IPs
                    logging.warning(f"Removing IP {ip} from active list due to {status}: {message}")
            elif result is not None:
                all_data.update(result)

        keys_to_remove = {"4194303", "4194304"}  
        cleaned_data = {ip: remove_entries(data, keys_to_remove) for ip, data in all_data.items()}

        # Create links based on the cleaned data
        data_with_links = create_links(cleaned_data)

        # Process BACNet/SC links after the create_links function
        process_bacnet_sc_links(data_with_links["Nodes"], data_with_links["Links"])  # Pass both Nodes and Links

        # Reorganize the data and continue with further data processing
        reorganized_data = reorganize_data(data_with_links)

        # Remove unnecessary sections
        for ip, content in reorganized_data.items():
            if "Local GFX Network Values" in content:
                del content["Local GFX Network Values"]
            if "Remote BACnet Data" in content:
                del content["Remote BACnet Data"]
            if "Remote Modbus Data" in content:
                del content["Remote Modbus Data"]

        # Clean up entries using substrings
        substrings_to_remove = ["network-policy", "connection-status", "status"]
        for node_id, node_data in reorganized_data["Nodes"].items():
            reorganized_data["Nodes"][node_id] = remove_entries(node_data, set(), substrings_to_remove)

        # Remove any entries matching device IPs
        for ip in list(reorganized_data.keys()):
            if ip in device_ip_addresses:
                del reorganized_data[ip]

        # Final processing: calculate cumulative counts
        final_data = calculate_cumulative_counts(reorganized_data)

        # Set loading state and return the final data
        final_data["failed_ips"] = list(failed_ip_addresses)
        final_data["loading"] = False  # Set loading to False
        return final_data

async def periodic_fetch():
    global all_network_values_global, device_ip_addresses, device_username, device_password
    while True:
        try:
            logging.info("Periodic fetch task started")
            all_network_values_global["loading"] = True
            all_network_values_global = await fetch_all_data(device_ip_addresses, device_username, device_password)
            logging.info("Periodic fetch task completed")
            all_network_values_global["loading"] = False
            await asyncio.sleep(30)  # Wait for 30 seconds after fetching
        except Exception as e:
            logging.error(f"Error in periodic fetch task: {str(e)}")
            all_network_values_global["loading"] = False
            await asyncio.sleep(30)  # Wait before retrying

def run_periodic_fetch():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(periodic_fetch())

@app.route('/api/data', methods=['GET'])
def get_data():
    return jsonify(all_network_values_global)

@app.route('/api/data', methods=['POST'])
async def update_data():
    global initial_fetch_completed, all_network_values_global, device_username, device_password, device_ip_addresses
    all_network_values_global["loading"] = True
    ip_input = request.json.get('ip_addresses', '')
    device_ip_addresses = set(parse_ip_addresses(ip_input))  # Ensure it's a set
    device_username = request.json.get('username', '')
    device_password = request.json.get('password', '')
    if not initial_fetch_completed or device_ip_addresses != set(all_network_values_global.get('ip_addresses', [])):
        all_network_values_global = await fetch_all_data(device_ip_addresses, device_username, device_password)
        all_network_values_global['ip_addresses'] = list(device_ip_addresses)  # Convert set to list for JSON
        initial_fetch_completed = True
    all_network_values_global["loading"] = False
    return jsonify(all_network_values_global)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico')

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    all_network_values_global = loop.run_until_complete(fetch_all_data(device_ip_addresses, device_username, device_password))
    initial_fetch_completed = True
    thread = threading.Thread(target=run_periodic_fetch)
    thread.daemon = True
    thread.start()
    app.run(debug=False)