import csv
import json
import sys
from json.decoder import JSONDecodeError

# This script converts a BigQuery CSV export file in a ndjson (JSON newline
# delimited file) format
# BigQuery CSV contains JSON strings for STRUCT fields, this script will try
# to detect JSON row values and parse them.
# The output is an ndjson file

def make_json(csvReader):
    for row in csvReader:
        item = {}
        for k,v in row.items():
            # some values may be JSON strings, try to identify them by being enclosed in {}
            if v.startswith("{") and v.endswith("}"):
                # try to parse JSON or add data as is on failure, in case even if the value is 
                # enclosed in {} is not a valid JSON string
                try:
                    keydata = json.loads(v)
                    print(k, v, keydata)
                    item[k] = keydata[k]
                except JSONDecodeError as e:
                    item[k] = v
            else:
                item[k] = v

        yield item

# csv
infile = sys.argv[0]
# json
outfile = "test-data.ndjson"
write = True

with open(infile, encoding='utf-8') as csvf:
    csvReader = csv.DictReader(csvf)
    with open(outfile, 'w', encoding='utf-8') as jsonf:
        for item in make_json(csvReader):
            #  print(item)
            if write:
                jsonf.write("{}\n".format(json.dumps(item)))


