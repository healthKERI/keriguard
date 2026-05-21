# -*- encoding: utf-8 -*-
"""
Generate cli tool for schema SAID and edge alignment

"""

import argparse
import json
from pathlib import Path

from keri.core import coring

parser = argparse.ArgumentParser(
    description="Generate SAIDS for schema and connect the SAIDs"
)
parser.add_argument(
    "--dir", "-d", help="localtion of the schema to generate", required=True
)
parser.set_defaults(handler=lambda args: handler(args), transferable=True)


def handler(args):
    """
    Process all schemas in directory with schema-map relationships.

    Args:
        args: Parsed command line arguments containing dir path

    Returns:
        None
    """
    dir_path = args.dir

    print(f"Processing schemas in: {dir_path}")

    # Phase 1: Load
    schema_map = load_schema_map(dir_path)
    schemas = load_all_schemas(dir_path)

    if not schemas:
        print("No schemas found")
        return

    print(f"Loaded {len(schemas)} schemas")

    # Phase 2: Determine processing order
    try:
        processing_order = topological_sort(schemas, schema_map)
    except ValueError as e:
        print(f"Error: {e}")
        return

    print(f"Processing order: {' -> '.join(processing_order)}")

    # Phase 3 & 4: Process each schema (update edges, generate SAIDs)
    for cred_type in processing_order:
        schema_info = schemas[cred_type]
        schema = schema_info["schema"]

        print(f"\nProcessing: {cred_type}")

        # Update edge constraints if this schema has edges
        if cred_type in schema_map:
            edges_map = schema_map[cred_type]
            update_edge_constraints(schema, edges_map, schemas)
            print(f"  Updated {len(edges_map)} edge constraint(s)")

        # Generate SAIDs for this schema
        populate_saids(schema)
        schema_info["said"] = schema["$id"]  # Store for other schemas to reference
        print(f"  Generated SAID: {schema['$id'][:20]}...")

        # Phase 5: Save
        __save(schema_info["path"], schema)
        print(f"  Saved to: {Path(schema_info['path']).name}")

    print(f"\nSuccessfully processed {len(schemas)} schemas")


def __load(p):
    ff = open(p, "r")
    jsn = json.load(ff)
    ff.close()
    return jsn


def load_schema_map(dir_path: str) -> dict:
    """
    Load and parse schema-map.json from the directory.

    Args:
        dir_path: Path to directory containing schema-map.json

    Returns:
        Dictionary mapping credential types to their edge relationships,
        or empty dict if schema-map.json doesn't exist
    """
    map_path = Path(dir_path) / "schema-map.json"
    if not map_path.exists():
        return {}  # No map = no edges to update
    with open(map_path) as f:
        return json.load(f)


def load_all_schemas(dir_path: str) -> dict:
    """
    Load all .json files in directory except schema-map.json.

    Args:
        dir_path: Path to directory containing schema files

    Returns:
        Dictionary mapping credentialType to schema info:
        {credentialType: {'path': filepath, 'schema': dict, 'said': None}}
    """
    schemas = {}
    for filepath in Path(dir_path).glob("*.json"):
        if filepath.name == "schema-map.json":
            continue

        schema_dict = __load(str(filepath))
        cred_type = schema_dict.get("credentialType")

        if not cred_type:
            print(f"Warning: {filepath.name} missing credentialType, skipping")
            continue

        schemas[cred_type] = {
            "path": str(filepath),
            "schema": schema_dict,
            "said": None,  # Will be populated after saidification
        }

    return schemas


def topological_sort(schemas: dict, schema_map: dict) -> list:
    """
    Return credential types in dependency order (leaves first).
    Uses Kahn's algorithm for topological sorting.

    Args:
        schemas: Dictionary of loaded schemas
        schema_map: Dictionary of edge relationships

    Returns:
        List of credential types in processing order

    Raises:
        ValueError: If circular dependency detected
    """
    # Build dependency graph
    in_degree = {ct: 0 for ct in schemas}
    adjacency = {ct: [] for ct in schemas}

    for cred_type in schemas:
        if cred_type in schema_map:
            for _, ref_type in schema_map[cred_type].items():
                if ref_type in schemas:  # Only count existing schemas
                    adjacency[ref_type].append(cred_type)
                    in_degree[cred_type] += 1

    # Kahn's algorithm
    queue = [ct for ct, degree in in_degree.items() if degree == 0]
    result = []

    while queue:
        node = queue.pop(0)
        result.append(node)

        for neighbor in adjacency[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    # Check for cycles
    if len(result) != len(schemas):
        raise ValueError("Circular dependency detected in schema map")

    return result


def update_edge_constraints(schema: dict, edges_map: dict, schemas: dict):
    """
    Update edge s.const values with referenced schema SAIDs.

    Args:
        schema: The schema dictionary to update
        edges_map: Dict of {ReferencedCredType: edgeName} for this schema
        schemas: All loaded schemas with their SAIDs
    """
    if "properties" not in schema or "e" not in schema["properties"]:
        return  # No edges block

    edges_block = schema["properties"]["e"]
    if "oneOf" not in edges_block or len(edges_block["oneOf"]) < 2:
        return  # No expanded edge definition

    expanded_edges = edges_block["oneOf"][1]
    if "properties" not in expanded_edges:
        return

    edge_props = expanded_edges["properties"]

    # Update each edge constraint
    for edge_name, ref_cred_type in edges_map.items():
        if edge_name not in edge_props:
            print(f"Warning: Edge property '{edge_name}' not found in schema")
            continue

        if ref_cred_type not in schemas:
            print(f"Warning: Referenced type '{ref_cred_type}' not found")
            continue

        ref_said = schemas[ref_cred_type]["said"]
        if not ref_said:
            raise ValueError(f"SAID not yet generated for {ref_cred_type}")

        # Navigate to s.const and update
        edge_def = edge_props[edge_name]
        if "properties" in edge_def and "s" in edge_def["properties"]:
            edge_def["properties"]["s"]["const"] = ref_said


def __save(p, d):
    s = open(p, "w")
    s.write(json.dumps(d, indent=2))
    s.close()


def populate_saids(
    d: dict, idage: str = coring.Saids.dollar, code: str = coring.MtrDex.Blake3_256
):
    if "properties" in d:
        props = d["properties"]

        # check for top level ids
        for v in ["a", "e", "r"]:
            if v in props and "$id" in props[v]:
                vals = props[v]
                vals[idage] = coring.Saider(sad=vals, code=code, label=idage).qb64
            elif v in props and "oneOf" in props[v]:
                if isinstance(props[v]["oneOf"], list):
                    # check each 'oneOf' for an id
                    ones = props[v]["oneOf"]
                    for o in ones:
                        if isinstance(o, dict) and idage in o:
                            o[idage] = coring.Saider(sad=o, code=code, label=idage).qb64

    d[idage] = coring.Saider(sad=d, code=code, label=idage).qb64

    return d
