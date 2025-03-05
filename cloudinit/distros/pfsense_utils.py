# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import logging

import lxml.etree as ET

from cloudinit import subp

LOG = logging.getLogger(__name__)

def _element_to_dict(element):
    """
    Recursively converts an ElementTree Element to a Python dictionary.
    """
    # If the element has no children, return its text directly (if available)
    if not list(element):  # No child elements
        return element.text.strip() if element.text and element.text.strip() else None

    # If the element has children, construct a dictionary
    obj = {}
    # Add attributes of the element (if any)
    obj.update(element.attrib)

    # Process child elements
    for child in element:
        child_obj = _element_to_dict(child)
        if child.tag not in obj:
            obj[child.tag] = child_obj
        else:
            # If multiple children have the same tag, convert to a list
            if not isinstance(obj[child.tag], list):
                obj[child.tag] = [obj[child.tag]]
            obj[child.tag].append(child_obj)

    return obj

def _dict_to_element(tag, data):
    """
    Recursively converts a Python dictionary to an ElementTree Element.
    """
    # Create the root element
    element = ET.Element(tag)

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                # Handle list of elements with the same tag
                for item in value:
                    element.append(_dict_to_element(key, item))
            elif isinstance(value, dict):
                # Handle nested dictionaries
                element.append(_dict_to_element(key, value))
            else:
                subelement = ET.Element(key)
                # Handle attributes or text content
                if value is None :
                    subelement.text = ""
                else:
                    subelement.text = value
                element.append(subelement)
    else:
        # If the data is a simple value, set it as text
        if data is None:
            element.text = ""
        else:
            element.text = str(data)

    return element

def get_config_elements(tree_path, fp="/cf/conf/config.xml"):
    """
    For the given xml path in key, get the element
    """

    # Find element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    nodes = root.xpath(tree_path)
    if nodes is None:
        return False

    # Return a list of dictionaries if multiple elements match
    return [_element_to_dict(node) for node in nodes] or []

def append_config_element(tree_path, element, fp="/cf/conf/config.xml"):
    """
    For the given xml path, create an element with the specified properties.
    """

    parent_path = tree_path.rsplit("/", 1)[0]
    tag = tree_path.rsplit("/", 1)[1]

    # Find parent element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    parent = root.xpath(parent_path)[0]
    if parent is None:
        raise ValueError("No such key: %s" % tree_path)

    # Append element to parent node
    parent.append(_dict_to_element(tag, element))

    # Write changes to file
    tree.write(fp, pretty_print=True)

def replace_config_element(tree_path, key, value, node, fp="/cf/conf/config.xml"):
    """
    For the given xml path, replace the value of the specified element
    """

    tag = tree_path.rsplit("/", 1)[1]

    # Find existing element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    nodes = root.xpath(tree_path)
    if nodes is None:
        raise ValueError("No such key: %s" % tree_path)

    old_node = None
    for n in nodes:
        if n.find(key).text == value:
            old_node = n
            break

    # If element does not exist, append new element
    if old_node is None:
        append_config_element(tree_path, node)
        return

    # Swap old element with new element
    parent = old_node.getparent()
    parent.remove(old_node)
    parent.append(_dict_to_element(tag, node))

    # Write changes to file
    tree.write(fp, pretty_print=True)

def remove_config_element(tree_path, key=None, value=None, fp="/cf/conf/config.xml"):
    """
    For the given xml path, remove the element with the specified value
    """

    # Find existing element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    nodes = root.xpath(tree_path)

    # Remove element from parent node
    # if no key is specified, remove all elements
    for n in nodes:
        if (key is None or value is None) or (key in n and n["key"].text == value):
            parent = n.getparent()
            parent.remove(n)

    # Write changes to file
    tree.write(fp, pretty_print=True)

def get_config_values(tree_path, fp="/cf/conf/config.xml"):
    """
    For the given xml path in key, get the value
    """

    # Find element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    node = root.xpath(tree_path)
    if node is None:
        return False

    return [node.text for node in node]

def set_config_value(tree_path, value, fp="/cf/conf/config.xml"):
    """
    For the givem xml path, set the value of the specified element.
    Only acts upon the first element found.
    """

    parent_path = tree_path.rsplit("/", 1)[0]
    tag = tree_path.rsplit("/", 1)[1]

    # Find parent element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    node = root.xpath(tree_path)

    # Check if element exists
    if node is None or len(node) == 0:
        parent = root.xpath(parent_path)[0]
        node = ET.element(tag)
        parent.append(node)
    else:
        node = node[0]

    # Set element value
    node.text = value

    # Write changes to file
    tree.write(fp, pretty_print=True)

def reload_config():
    """
    Tell pf to reload its configuration
    """

    # Force-stop SSH to prevent race condition when it's restarted
    # by rc.reload_all
    reload_command = "pfSsh.php playback svc stop sshd && sleep 5 && /etc/rc.reload_all"
    return subp.subp(["bash", "-c", reload_command], capture=True, rcs=[0])

def sync_users_groups():
    """
    Generate system accounts from pfSense config
    """

    php_command = """
    require_once('/etc/inc/globals.inc');
    require_once('/etc/inc/config.inc');
    require_once('/etc/inc/auth.inc');
    global $config;
    $config = parse_config(true);
    local_reset_accounts();
    """

    return subp.subp(["php", "-r", php_command], capture=True)

def sync_hostname():
    """
    Set hostname based on pfSense config
    """

    php_command = """
    require_once('/etc/inc/globals.inc');
    require_once('/etc/inc/config.inc');
    global $config;
    $config = parse_config(true);
    system_hostname_configure();
    """

    return subp.subp(["php", "-r", php_command], capture=True)

def sync_hosts():
    """
    Set hostname based on pfSense config
    """

    php_command = """
    require_once('/etc/inc/globals.inc');
    require_once('/etc/inc/config.inc');
    global $config;
    $config = parse_config(true);
    system_hosts_generate();
    """

    return subp.subp(["php", "-r", php_command], capture=True)

def sync_resolvconf():
    """
    Generate resolvconf based on pfSense config
    """

    php_command = """
    require_once('/etc/inc/globals.inc');
    require_once('/etc/inc/config.inc');
    global $config;
    $config = parse_config(true);
    system_resolvconf_generate();
    """

    return subp.subp(["php", "-r", php_command], capture=True)