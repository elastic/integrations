import pytest
from .. import report

SAMPLE_TEST_NAMES = [
    "io.jenkins.blueocean.service.embedded.rest.junit."
    "BlueJUnitTestResult:aws.cloudtrail%3Ajunit%2Faws%2Fc"
    "loudtrail%2FCheck_integrations___aws___aws__check___"
    "pipeline_test__test_console_login_json_log"
]


def test_setup_logging(default_args):
    """
    GIVEN that the arguments contain the `verbose` flag
    WHEN the setup_logging() function is called
    THEN the return is set to `DEBUG`
    """
    assert report.setup_logging(default_args.verbose) == 'INFO'


def test_setup_logging_verbose(verbose_args):
    """
    GIVEN that the arguments contain the `verbose` flag
    WHEN the setup_logging() function is called
    THEN the return is set to `DEBUG`
    """
    assert report.setup_logging(verbose_args) == 'DEBUG'


@pytest.mark.parametrize('test_name', SAMPLE_TEST_NAMES)
def test_classify(test_name):
    """
    GIVEN a set of test names
    WHEN those test names are passed to the classifier
    THEN the classifier identifies their package, component, and test type
    """
    assert report.classify(test_name) == ('aws', 'cloudtrail', 'pipeline')


def test_extract_tests(mock_es_return):
    """
    GIVEN an response from the Elasticsearch cluster which contains tests
    WHEN the documents from the response are passed to extract_tests
    THEN a list of tests is returned
    """
    # Select just a single job to test
    document = mock_es_return['hits']['hits'][0]
    ret = report.extract_tests(document)
    assert len(ret) == 153
    # Select just a single return to examine
    test_ret = ret[-1]
    assert test_ret.package == 'zeek'
    assert test_ret.timestamp == '2021-01-07T20:48:18.256+0000'
    assert test_ret.type == 'system'
    assert test_ret.result == 'PASSED'
    # TODO test_ret.version
    # TODO test_ret.integration_version
    assert test_ret.component == 'socks'


def test_status(tests_fixture_even, packages_fixture):
    """
    GIVEN a set of tests
    WHEN those tests are passed to the test_status() func
    THEN a status map is generated
    """
    got = report.test_status(tests_fixture_even)
    for package in packages_fixture:
        assert got[package] == {'PASSED': 6,
                                'FAILED': 6, 'ERROR': 6, 'UNKNOWN': 6}


def test_status_geometric(test_fixture_status_geometric):
    """
    GIVEN a set of tests with varying results
    WHEN those tests are passed the test_status() func
    THEN a status map is generated
    """
    want = \
        {'fake_apache': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_auditd': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_aws': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_azure': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_cef': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_checkpoint': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_cisco': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_crowdstrike': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_elastic_agent': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_fortinet': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_google_workspace': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_haproxy': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_iis': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_iptables': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_juniper': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_kafka': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_kubernetes': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_linux': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_log': {'ERROR': 0, 'FAILED': 0, 'PASSED': 3, 'UNKNOWN': 0},
         'fake_microsoft': {'ERROR': 0, 'FAILED': 1, 'PASSED': 2, 'UNKNOWN': 0},
         'fake_mongodb': {'ERROR': 0, 'FAILED': 3, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_mysql': {'ERROR': 0, 'FAILED': 3, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_nats': {'ERROR': 0, 'FAILED': 3, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_netflow': {'ERROR': 0, 'FAILED': 3, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_nginx': {'ERROR': 0, 'FAILED': 3, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_nginx_ingress_controller': {'ERROR': 0,
                                           'FAILED': 3,
                                           'PASSED': 0,
                                           'UNKNOWN': 0},
         'fake_o365': {'ERROR': 0, 'FAILED': 3, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_okta': {'ERROR': 0, 'FAILED': 3, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_osquery': {'ERROR': 0, 'FAILED': 3, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_panw': {'ERROR': 0, 'FAILED': 3, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_postgresql': {'ERROR': 1, 'FAILED': 2, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_prometheus': {'ERROR': 3, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_rabbitmq': {'ERROR': 3, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_redis': {'ERROR': 3, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_santa': {'ERROR': 3, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_suricata': {'ERROR': 3, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 0},
         'fake_system': {'ERROR': 0, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 3},
         'fake_windows': {'ERROR': 0, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 3},
         'fake_zeek': {'ERROR': 0, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 3},
         'fake_zookeeper': {'ERROR': 0, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 3},
         'fake_zoom': {'ERROR': 0, 'FAILED': 0, 'PASSED': 0, 'UNKNOWN': 3}}
    got = report.test_status(test_fixture_status_geometric)
    assert got == want

def test_frequency_linear(test_fixture_freq_linear, packages_fixture):
    want = \
        {
            'fake_apache': 0,
            'fake_auditd': 3,
            'fake_aws': 6,
            'fake_azure': 9,
            'fake_cef': 12,
            'fake_checkpoint': 15,
            'fake_cisco': 18,
            'fake_crowdstrike': 21,
            'fake_elastic_agent': 24,
            'fake_fortinet': 27,
            'fake_google_workspace': 30,
            'fake_haproxy': 33,
            'fake_iis': 36,
            'fake_iptables': 39,
            'fake_juniper': 42,
            'fake_kafka': 45,
            'fake_kubernetes': 48,
            'fake_linux': 51,
            'fake_log': 54,
            'fake_microsoft': 57,
            'fake_mongodb': 60,
            'fake_mysql': 63,
            'fake_nats': 66,
            'fake_netflow': 69,
            'fake_nginx': 72,
            'fake_nginx_ingress_controller': 75,
            'fake_o365': 78,
            'fake_okta': 81,
            'fake_osquery': 84,
            'fake_panw': 87,
            'fake_postgresql': 90,
            'fake_prometheus': 93,
            'fake_rabbitmq': 96,
            'fake_redis': 99,
            'fake_santa': 102,
            'fake_suricata': 105,
            'fake_system': 108,
            'fake_windows': 111,
            'fake_zeek': 114,
            'fake_zookeeper': 117,
            'fake_zoom': 120
        }
    got = report.test_frequency(
        test_fixture_freq_linear,
        packages_fixture,
        limit=-1,
        include_untested=True
        )
    assert got == want


def test_frequency_exclude_untested(test_fixture_subset_10, packages_fixture):
    """
    GIVEN a set of tests and a set of packages
    WHEN those tests and packages are provides to the test_frequency algorithm
    AND the `include_untested` flag is set to `False`
    THEN no untested packages appear in the return
    """
    got = report.test_frequency(
        test_fixture_subset_10,
        packages_fixture, limit=-1,
        include_untested=False
        )
    assert len(got.keys()) == 10

def test_frequency(tests_fixture_even, packages_fixture):
    """
    GIVEN a set of tests and a set of packages
    WHEN those tests and packages are provided to the test_frequency algorithm
    THEN a map of test frequency is generated and returned
    """
    want = \
        {
            'fake_apache': 24,
            'fake_auditd': 24,
            'fake_aws': 24,
            'fake_azure': 24,
            'fake_cef': 24,
            'fake_checkpoint': 24,
            'fake_cisco': 24,
            'fake_crowdstrike': 24,
            'fake_elastic_agent': 24,
            'fake_fortinet': 24,
            'fake_google_workspace': 24,
            'fake_haproxy': 24,
            'fake_iis': 24,
            'fake_iptables': 24,
            'fake_juniper': 24,
            'fake_kafka': 24,
            'fake_kubernetes': 24,
            'fake_linux': 24,
            'fake_log': 24,
            'fake_microsoft': 24,
            'fake_mongodb': 24,
            'fake_mysql': 24,
            'fake_nats': 24,
            'fake_netflow': 24,
            'fake_nginx': 24,
            'fake_nginx_ingress_controller': 24,
            'fake_o365': 24,
            'fake_okta': 24,
            'fake_osquery': 24,
            'fake_panw': 24,
            'fake_postgresql': 24,
            'fake_prometheus': 24,
            'fake_rabbitmq': 24,
            'fake_redis': 24,
            'fake_santa': 24,
            'fake_suricata': 24,
            'fake_system': 24,
            'fake_windows': 24,
            'fake_zeek': 24,
            'fake_zookeeper': 24,
            'fake_zoom': 24
        }
    got = report.test_frequency(tests_fixture_even, packages_fixture, limit=-1)
    assert got == want

@pytest.mark.parametrize("requested_limit", range(0, 20))
def test_frequency_limit_range(requested_limit, tests_fixture_even, packages_fixture):
    """
    GIVEN a set of tests and a set of packages
    WHEN those tests and packages are provided to the test_frequency algorithm
         and the requested limit is not the default
    THEN the correct number of results are returned
    """
    got = report.test_frequency(tests_fixture_even, packages_fixture, limit=requested_limit)
    assert len(got.keys()) == requested_limit


def test_status_collate_by_success(test_status_range):
    """
    GIVEN a set of tests where two tests pass and one fails and one has an
        error
    WHEN the tests are passed to test_status with the collate_by flag set to
        collate just passing tests
    THEN we get a dictionary with just the two passing tests
    """
    got = report.test_status(test_status_range, collate_by=['PASSED'])
    assert got == {'package-p': 2}


def test_status_collate_by_failure_and_error(test_status_range):
    got = report.test_status(test_status_range, collate_by=['FAILED', 'ERROR'])
    assert got == {'package-f-1': 1, 'package-e-1': 1}


@pytest.mark.parametrize("requested_limit", range(0, 20))
def test_status_limit_range(requested_limit, tests_fixture_even):
    """
    GIVEN a set of tests
    WHEN those tests and packages are provided to the test_status function
         and the requested limit is not the default
    THEN the correct number of results are returned
    """
    got = report.test_status(
        tests_fixture_even,
        limit=requested_limit,
        collate_by=['PASSED']
        )
    assert len(got.keys()) == requested_limit
