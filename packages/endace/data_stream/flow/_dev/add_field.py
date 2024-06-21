import json, os, collections
from datetime import datetime
import time

events_path = os.getcwd() + "/data_stream/flow/_dev/test/pipeline/test-flow-events.json"
expected_events_path = os.getcwd() + "/data_stream/flow/_dev/test/pipeline/test-flow-events.json-expected.json"

with open(events_path, 'r') as f:
    events = json.load(f, object_pairs_hook=collections.OrderedDict)

with open(expected_events_path, 'r') as ef:
    expected_events = json.load(ef, object_pairs_hook=collections.OrderedDict)


def remove_metadata():
    new_events = {"events":[]}
    for event in events['events']:
        if '_source' in event:
            new_events['events'].append(event['_source'])
            
    return new_events

def process_events():
    for event in events['events']:
        if '_conf' not in event:
            event['_conf'] = {}
        event['_conf']['endace_url'] = 'https://test.test.local'
        event['_conf']['endace_datasources'] = 'tag:rotation-file'
        event['_conf']['endace_tools'] = 'trafficOverTime_by_app,conversations_by_ipaddress'
        event['_conf']['endace_lookback'] = 10


        # Convert event.start to epoch
        if 'event' in event and 'start' in event['event']:
            start_str = event['event']['start']
            # Assuming the date format is ISO 8601, e.g., "2023-01-01T00:00:00Z"
            start_dt = datetime.strptime(start_str, "%Y-%m-%dT%H:%M:%SZ")
            event['_conf']['event']['start'] = int(time.mktime(start_dt.timetuple()))

        # Convert event.end to epoch
        if 'event' in event and 'end' in event['event']:
            end_str = event['event']['end']
            # Assuming the date format is ISO 8601, e.g., "2023-01-01T00:00:00Z"
            end_dt = datetime.strptime(end_str, "%Y-%m-%dT%H:%M:%SZ")
            event['_conf']['event']['end'] = int(time.mktime(end_dt.timetuple()))


def process_expected_events():
    for event in expected_events['expected']:
        if '_conf' in event:
            del event['_conf']
        event['ecs']['version'] = "8.11.0"
    # expected_events['expected'] = expected_events.pop('events')



process_events()

process_expected_events()

# events = remove_metadata()
# Write Events            
with open(events_path, 'w') as f:
    json.dump(events, f, indent=4)


# Write Expected Events            
with open(expected_events_path, 'w') as ef:
    json.dump(expected_events, ef, indent=4)

