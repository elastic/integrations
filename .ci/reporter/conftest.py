import os
import json
import math
import pytest
import argparse
from collections import namedtuple


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

@pytest.fixture
def test_fixture_freq_linear():
    """
    A test fixture where the number of tests per package
    just increases in a linear fashion, incremented by 1
    """
    tests = []
    fake_components = ('fake_component_1', 'fake_component_2', 'fake_component_3')
    fake_date = '2021-01-07T20:48:18.256+0000'

    test_types = ('system', 'pipeline')
    Test = namedtuple("Test", [
        "timestamp",  # Time of test
        "package",  # Package being tested
        "type",  # Type of test: pipeline or system
        "result",  # Test result: pass, fail, or error
        "version",  # Stack version used in test
        "integration_version",  # Integration version used in test (only applicable to system tests)
        "component"  # Component for the package. TODO this might not be the right language?
        ])

    for package_counter, package in enumerate(_packages()):
        for _ in range(0, package_counter):
            for component in fake_components:
                test = Test(
                        fake_date,
                        package,
                        'fake_status',
                        'FAKE_RESULT',
                        -1,
                        -1,
                        component
                       )
                tests.append(test)
    return tests



@pytest.fixture
def test_fixture_status_geometric():
    """
    A fixture which sets status with n/2 distribution
    """
    tests = []
    fake_components = ('fake_component_1', 'fake_component_2', 'fake_component_3')
    fake_date = '2021-01-07T20:48:18.256+0000'

    test_statuses = ('PASSED', 'FAILED', 'ERROR', 'UNKNOWN')
    test_types = ('system', 'pipeline')

    Test = namedtuple("Test", [
        "timestamp",  # Time of test
        "package",  # Package being tested
        "type",  # Type of test: pipeline or system
        "result",  # Test result: pass, fail, or error
        "version",  # Stack version used in test
        "integration_version",  # Integration version used in test (only applicable to system tests)
        "component"  # Component for the package. TODO this might not be the right language?
        ])

    numerator = divisor = 1
    for _ in range(1, len(test_statuses)):
        numerator *= 2
        divisor += numerator

    total_projected_tests = 0
    distribution_marker = 0
    # First calculate total projected
    for package in _packages():
        for component in fake_components:
            total_projected_tests += 1
    # Now calculate and apply the distribution in a single loop
    loop_counter = 0
    for package in _packages():
        for component in fake_components:
            if math.floor(total_projected_tests - loop_counter) < math.floor((numerator / divisor) * total_projected_tests):
                numerator /= 2
                distribution_marker += 1
            try:
                test = Test(
                        fake_date,
                        package,
                        'system',
                        test_statuses[distribution_marker],
                        -1,
                        -1,
                        component
                        )
            except IndexError:
                # This ends up being psedudo-geometric because a tiny amount of spillover ends up
                # in the last bucket due to imperfect division but this is fine since our only goal
                # is to distribute the results in a predictable  but still-distributed fashion.
                # Don't use this approach if you need precice geometric regression.
                test = Test(
                        fake_date,
                        package,
                        'system',
                        test_statuses[len(test_statuses) - 1],
                        -1,
                        -1,
                        component
                        )
            tests.append(test)
            loop_counter += 1
    return tests


@pytest.fixture
def tests_fixture_even():
    """
    A fixture providing a few tests using our named tuple structure
    """
    tests = []
    fake_components = ('fake_component_1', 'fake_component_2', 'fake_component_3')
    fake_date = '2021-01-07T20:48:18.256+0000'

    test_statuses = ('PASSED', 'FAILED', 'ERROR', 'UNKNOWN')
    test_types = ('system', 'pipeline')

    Test = namedtuple("Test", [
        "timestamp",  # Time of test
        "package",  # Package being tested
        "type",  # Type of test: pipeline or system
        "result",  # Test result: pass, fail, or error
        "version",  # Stack version used in test
        "integration_version",  # Integration version used in test (only applicable to system tests)
        "component"  # Component for the package. TODO this might not be the right language?
        ])

    for package in _packages():
        for component in fake_components:
            for status in test_statuses:
                for test_type in test_types:
                    test = Test(fake_date, package, test_type, status, -1, -1, component)
                    tests.append(test)
#    import pprint
#    pprint.pprint(tests)
    return tests

@pytest.fixture
def packages_fixture():
    return _packages()

def _packages():
    """
    A fixture providing list of packages which would otherwise be retreived
    from GitHub, by listing the packages found here:

    https://github.com/elastic/integrations/tree/master/packages
    """
    return [
            "fake_apache",
            "fake_auditd",
            "fake_aws",
            "fake_azure",
            "fake_cef",
            "fake_checkpoint",
            "fake_cisco",
            "fake_crowdstrike",
            "fake_elastic_agent",
            "fake_fortinet",
            "fake_google_workspace",
            "fake_haproxy",
            "fake_iis",
            "fake_iptables",
            "fake_juniper",
            "fake_kafka",
            "fake_kubernetes",
            "fake_linux",
            "fake_log",
            "fake_microsoft",
            "fake_mongodb",
            "fake_mysql",
            "fake_nats",
            "fake_netflow",
            "fake_nginx",
            "fake_nginx_ingress_controller",
            "fake_o365",
            "fake_okta",
            "fake_osquery",
            "fake_panw",
            "fake_postgresql",
            "fake_prometheus",
            "fake_rabbitmq",
            "fake_redis",
            "fake_santa",
            "fake_suricata",
            "fake_system",
            "fake_windows",
            "fake_zeek",
            "fake_zookeeper",
            "fake_zoom",
            ]
