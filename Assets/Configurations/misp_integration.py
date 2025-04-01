from pymisp import PyMISP
from opensearchpy import OpenSearch

# MISP Configuration
misp_url = 'https://192.168.1.130'  # Your MISP instance URL
misp_key = 'eUyROKNWX7gFmPnyDjxqvFs8GCQ5zLVmC7fvRzmG'  # Your MISP API key
misp_verifycert = False  # Set to True for valid SSL certificates

# OpenSearch Configuration
opensearch_host = 'https://192.168.1.132:9200'  # Your OpenSearch cluster URL
opensearch_auth = ('admin', 'Strongpassword@1234')  # Your OpenSearch credentials
index_name = 'misp-threat-intel'  # Updated index name for clarity

# Initialize MISP and OpenSearch clients
misp = PyMISP(misp_url, misp_key, misp_verifycert)
client = OpenSearch(
    [opensearch_host],
    http_auth=opensearch_auth,
    use_ssl=True,
    verify_certs=False
)

# Function to transform MISP event into key-value pairs
def transform_event(event):
    # Base structure for the transformed event
    transformed = {
        "event_id": event.get("Event", {}).get("id", ""),
        "event_description": event.get("Event", {}).get("info", ""),
        "event_date": event.get("Event", {}).get("date", ""),
        "threat_level_id": event.get("Event", {}).get("threat_level_id", ""),
        "attributes": {}
    }
    
    # Extract attributes (IoCs) into key-value pairs
    if "Attribute" in event.get("Event", {}):
        for attr in event["Event"]["Attribute"]:
            attr_type = attr.get("type", "unknown")
            attr_value = attr.get("value", "")
            attr_category = attr.get("category", "")
            # Use type and value as a key-value pair in the attributes dictionary
            transformed["attributes"][attr_type] = {
                "value": attr_value,
                "category": attr_category
            }
    
    return transformed

# Fetch and index MISP events
events = misp.search(controller='events', return_format='json')

# Process and index each event
indexed_count = 0
for event in events:
    # Transform the event into a key-value pair structure
    transformed_event = transform_event(event)
    
    # Index the transformed event into OpenSearch
    client.index(
        index=index_name,
        body=transformed_event,
        id=transformed_event["event_id"]  # Use event ID as the document ID
    )
    indexed_count += 1

print(f"Indexed {indexed_count} events into OpenSearch with key-value pair structure.")
