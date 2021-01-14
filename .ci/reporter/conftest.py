import os
import json
import pytest
import argparse


@pytest.fixture
def default_args():
    """
    A fixture which represents the parsed arguments
    to the script all as defaults. Where defaults are not
    set by the script, fake values are used.

    Note
    ----
    Additional arguments are also inserted via the wrap_env()
    fixture which is auto-used by tests
    """
    args = argparse.Namespace()
    args.verbose = False
    args.history = "7d"
    return args

@pytest.fixture
def verbose_args():
    """
    A fixture which represents the default
    args but with the `--verbose` flag set

    Note
    ----
    Additional arguments are also inserted via the wrap_env()
    fixture which is auto-used by tests
    """
    args = argparse.Namespace()
    args.history = "7d"
    args.verbose = True
    return args

@pytest.fixture(autouse=True)
def wrap_env():
    """
    Wraps all executions with default environment. This avoids
    triggering an error when default arguments are not present
    during argument parsing.
    """
    os.environ['ES_HOST'] = "http://fake_es_hostname"
    os.environ['ES_USER'] = "fake_username"
    os.environ['ES_PASS'] = "fake_password"

@pytest.fixture
def mock_es_return():
    """
    A sample raw return from Elasticserch which contains
    two tests.

    Pre-generated via the following query:

    GET /jenkins-builds*/_search
    {
      "size": 2,
      "query" : {
        "bool": {
          "must": [{
               "range" : {
                  "build.startTime": {
                  "gte": "now-7d"
                }
              }
            }],
          "filter":[
            {
              "term": {
                "job.fullName.keyword": "Ingest-manager/integrations/master"
              }
            }
          ]
        }
      }
    }
    """
    with open("mock_es_response.json", "r") as fh_:
        es_ret = json.load(fh_)
    return es_ret
