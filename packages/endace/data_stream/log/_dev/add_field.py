import json, os, collections, copy



events_path = os.getcwd() + "/data_stream/log/_dev/test/pipeline/test-netflow-log-events.json"
expected_events_path = os.getcwd() + "/data_stream/log/_dev/test/pipeline/test-netflow-log-events.json-expected.json"

with open(events_path, 'r') as f:
    events = json.load(f, object_pairs_hook=collections.OrderedDict)

with open(expected_events_path, 'r') as ef:
    expected_events = json.load(ef, object_pairs_hook=collections.OrderedDict)


# expected_events = copy.deepcopy(events)

def process_events():
    for event in events['events']:
        if '_conf' not in event:
            event['_conf'] = {}
        event['_conf']['endace_url'] = 'https://test.test.local'
        event['_conf']['endace_datasources'] = 'tag:rotation-file'
        event['_conf']['endace_tools'] = 'trafficOverTime_by_app,conversations_by_ipaddress'
        event['_conf']['endace_lookback'] = 10


def process_expected_events():
    for event in expected_events['expected']:
        if '_conf' in event:
            del event['_conf']
    # expected_events['expected'] = expected_events.pop('events')



process_events()

process_expected_events()


# Write Events            
with open(events_path, 'w') as f:
    json.dump(events, f, indent=4)


# Write Expected Events            
with open(expected_events_path, 'w') as ef:
    json.dump(expected_events, ef, indent=4)

