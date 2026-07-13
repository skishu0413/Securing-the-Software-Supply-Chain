"""
Parses pom.xml for Maven dependencies.

NOTE: xml.etree.ElementTree is used as a fallback. When defusedxml is
installed, it is used instead to harden against XML External Entity (XXE)
injection attacks. Using lxml directly without resolve_entities=False would
also introduce XXE risk.
"""
import re
import sys
import xml.etree.ElementTree as ET

try:
    import defusedxml.ElementTree as _defused_ET
    _USE_DEFUSED = True
except ImportError:
    _USE_DEFUSED = False
    print(
        "WARNING: defusedxml not installed; falling back to xml.etree.ElementTree. "
        "Install defusedxml to harden against XXE attacks.",
        file=sys.stderr
    )

_PROPERTY_RE = re.compile(r'^\$\{(.+)\}$')


def _collect_properties(root, ns_map: dict) -> dict:
    """Collect <properties> entries from root and <dependencyManagement>."""
    props = {}
    # Use namespace-aware path when a namespace is present, plain tag otherwise
    xpath = './/m:properties' if ns_map else './/properties'
    for props_el in root.findall(xpath, ns_map):
        for child in props_el:
            # strip namespace from tag
            tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
            if child.text:
                props[tag] = child.text.strip()
    return props


def parse_maven(file_path):
    """
    Parses a pom.xml file and returns a list of dependencies.
    """
    dependencies = []
    try:
        if _USE_DEFUSED:
            tree = _defused_ET.parse(file_path)
        else:
            tree = ET.parse(file_path)
    except ET.ParseError as e:
        print(f"Error parsing {file_path}: {e}", file=sys.stderr)
        return []

    root = tree.getroot()

    namespace = ''
    if '}' in root.tag:
        namespace = root.tag.split('}')[0][1:]

    ns_map = {'m': namespace} if namespace else {}

    properties = _collect_properties(root, ns_map)

    dep_xpath = './/m:dependency' if ns_map else './/dependency'
    for dep in root.findall(dep_xpath, ns_map):
        group_id_el = dep.find('m:groupId' if ns_map else 'groupId', ns_map)
        artifact_id_el = dep.find('m:artifactId' if ns_map else 'artifactId', ns_map)
        version_el = dep.find('m:version' if ns_map else 'version', ns_map)

        if group_id_el is None or artifact_id_el is None or version_el is None:
            continue

        version = version_el.text or ''
        match = _PROPERTY_RE.match(version)
        if match:
            prop_name = match.group(1)
            resolved = properties.get(prop_name)
            if resolved is None:
                print(
                    f"WARNING: Cannot resolve Maven property ${{{prop_name}}}; "
                    f"skipping {group_id_el.text}:{artifact_id_el.text}.",
                    file=sys.stderr
                )
                continue
            version = resolved

        package_name = f"{group_id_el.text}:{artifact_id_el.text}"
        dependencies.append({
            'name': package_name,
            'version': version,
            'group_id': group_id_el.text,
            'artifact_id': artifact_id_el.text,
        })

    return dependencies
