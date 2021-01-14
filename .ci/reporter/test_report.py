import pytest
from . import report
from unittest.mock import patch

SAMPLE_TEST_NAMES= [
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
    assert report.setup_logging(default_args) == 'INFO'

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


