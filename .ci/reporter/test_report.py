from . import report
from unittest.mock import patch


def test_gather_args():
    """
    GIVEN the report module is loaded directly
    WHEN the gather_args() function is called
    THEN the command line arguments are gathered
    """
    ret = report.gather_args()
    assert hasattr(ret, 'verbose')
    assert hasattr(ret, 'history')
    assert hasattr(ret, 'es_host')
    assert not hasattr(ret, 'should_not_exist')

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

