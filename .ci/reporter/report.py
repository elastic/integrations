#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations

"""
Integrations Test Reporter

This is a script which produces reports on various aspects
of package testing.
"""
import argparse
import logging
import os
from collections import namedtuple
from email.message import EmailMessage
from smtplib import SMTP

import jinja2
from elasticsearch import Elasticsearch
from github import Github


def setup_logging(verbose_flag: bool):
    """
    Setup the logger

    Parameters
    ----------
    verbose_flag : bool
        Set to true to enable verbose logging

    Note
    ----
    While this script uses the full Python logging library,
    we don't need sophisticated logging, therefore we make use
    the DEBUG level for debugging-style output and INFO
    for everything else.

    Returns
    -------
    str
        The log level which was set
    """
    if verbose_flag:
        log_level = 'DEBUG'
    else:
        log_level = 'INFO'

    logging.basicConfig(
            format='[%(levelname)s] %(asctime)s %(message)s',
            level=log_level
            )
    return log_level


def gather_args():
    """
    Gather the command line arguments

    Returns
    -------
    argparse.Namespace
        An object which contains the parsed args. Arguments
        are accessible as object attributes.
    """
    parser = argparse.ArgumentParser(
        description='Generate Integrations test report.'
        )
    parser.add_argument(
            "-v",
            "--verbose",
            help="Run with increased logging. "
            "Useful for development and debugging.",
            action="store_true"
            )
    parser.add_argument(
            "--timespan",
            help="The length of time to search back through for tests to be "
            "included in this report. Pass with a suffix of h (hours), "
            "d (days), m (months), or y (years). Ex: `--history=10D` to "
            "gather history for the previous 10 days.",
            default="7d"
            )

    es_group = parser.add_argument_group("Elasticsearch")

    es_group.add_argument(
            "--es-host",
            help="The URL of the Elasticsearch cluster which contains "
            "test results to be parsed. Can also be set with ES_HOST "
            "in the environment",
            default=os.environ.get("ES_HOST"),
            required="ES_HOST" not in os.environ
            )
    es_group.add_argument(
            "--es-user",
            help="The username to use to authenticate to the Elasticsearch "
            "cluster which contains test results to be parsed. Can also be "
            "set with ES_USER in the environment",
            default=os.environ.get("ES_USER"),
            required="ES_USER" not in os.environ
            )
    es_group.add_argument(
            "--es-pass",
            help="The username to use to authenticate to the Elasticsearch "
            "cluster which contains test results to be parsed. Can also be "
            "set with ES_USER in the environment",
            default=os.environ.get("ES_PASS"),
            required="ES_PASS" not in os.environ
            )
    parser.add_argument(
            "--gh-token",
            help="GitHub token which has read access the elastic/integrations "
            "repo",
            required="GH_TOKEN" not in os.environ
            )

    smtp_group = parser.add_argument_group(
        "Email",
        "Configuration for SMTP mailer"
        )

    smtp_group.add_argument(
            "--smtp-recipient",
            help="SMTP recipient. (Can be passed multiple times.)",
            required="SMTP_RECIP" not in os.environ,
            action="append"
    )
    smtp_group.add_argument(
            "--smtp-provider",
            help="SMTP provider to use",
            choices=["gmail"],
            required=False
    )
    smtp_group.add_argument(
            "--smtp-user",
            help="SMTP username to authenticate with",
            required="SMTP_USER" not in os.environ
    )
    smtp_group.add_argument(
            "--smtp-pass",
            help="SMTP password to authenticate with",
            required="SMTP_PASS" not in os.environ
    )
    parser.add_argument(
            "--include-untested",
            help="Include packages which are present in the repo but for "
                 "which no tests have been found. (Default: False)",
            action="store_true"
    )
    parser.add_argument(
            "--limit",
            help="Limit the number of tests displayed in reports",
            default=os.environ.get("TEST_LIMIT", 10),
            required=False
    )
    parser.add_argument(
            "--output",
            help="Where should we send the generated HTML",
            choices=["email", "stdout"],
            default="email"
    )
    return parser.parse_args()


def es_conn(hostname: str, username: str, password: str):
    """
    Connection to the Elasticsearch cluster where the test data is stored

    Parameters
    ----------
    str : hostname
        The hostname of the Elasticsearch instance to connect to

    str : username
        The username used to authenticate to the Elasticsearch instance

    str : password
        The password used to authenticate to the Elasticsearch instance

    Returns
    -------
    elasticsearch.Elasticsearch
        An Elasticsearch object which has been initialized and connected to
        the Elasticsearch cluster where the test data is stored.
    """
    return Elasticsearch([hostname], http_auth=(username, password))


def gh_conn(token: str):
    """
    Return a Github connection that is initialized and ready

    Parameters
    ----------
    str : token
        A valid GitHub token

    Returns
    -------
    GitHub
        An initialized GitHub object
    """
    return Github(token)


def gather_docs(conn, timespan: str):
    """
    Take a connected Elasticsearch instance and direct it to return documents
    going back from the present time extending backward to the given timespan.

    Parameters
    ----------
    Elasticsearch : es_conn
        A connected Elasticsearch instance

    str : timespan
        A timespan which is an integer followed immediately by a unit of time.
        Ex: 7d

    Returns
    -------
    dict
        A dictionary containing the results returned from Elasticsearch
    """
    query_body = \
        {
            "query": {
                "bool": {
                    "must": [{
                        "range": {
                            "build.startTime": {
                                "gte": "now-{}".format(timespan)
                            }
                        }
                    }],
                    "filter": [{
                        "term": {
                            "job.fullName.keyword":
                            "Ingest-manager/integrations/master"
                        }
                    }]
                }
            }
        }

    index_to_query = "jenkins-builds*"
    logging.debug(f"Querying Elasticsearch index [{index_to_query}] with query: {query_body}")  # noqa E205

    search_result = conn.search(body=query_body, index=index_to_query)
    logging.debug(f"Elasticsearch query returned: {search_result}")
    return search_result


def gather_gh_packages(gh, branch='master') -> list:
    """
    Gather a list of packages in the elastic/integrations repo

    Parameters
    ---------
    Github : gh
        A connected Github instance

    str : branch
        The branch of the project to search. Default: `master`.

    Returns
    -------
    list
        An unordered list of packages available in repo
    """
    packages = []
    repo = gh.get_repo("elastic/integrations")
    contents = repo.get_contents("packages", ref=branch)

    logging.debug(f"GitHub query to [{repo}] returned the following contents: {contents}")  # noqa E205

    for package in contents:
        package_name = package.path.split("/").pop()
        packages.append(package_name)
    return packages


def extract_tests(document: dict) -> list:
    """
    Given a document containing tests that has been returned
    from Elasticsearch, extract the set of tests it contains.

    Each test is returned as a named tuple

    Notes
    -----
    Do not depend on ordering in the returned list.

    Parameters
    ----------
    dict : Elasticsearch document

    Returns
    -------
    list
        A list of test named tuples
    """
    tests = []
    Test = namedtuple("Test", [
        # Time of test
        "timestamp",

        # Package being tested
        "package",

        # Type of test: pipeline or system
        "type",

        # Test result: pass, fail, or error
        "result",

        # Stack version used in test
        "version",

        # Integration version used in test(only applicable to system tests)
        "integration_version",

        # Component for the package. TODO this might not be the right language?
        "component"
        ]
        )

    for test in document['_source']['test']:
        package, component, test_type = classify(test["id"])
        composed_test = Test(
                document["_source"]["build"]["startTime"],
                package,
                test_type,
                test["status"],
                -1,  # `version` is a TODO
                -1,  # `integration_version` is a TODO
                component
                )
        logging.debug(f"Composed test: {composed_test}")
        tests.append(composed_test)
    return tests


def classify(name: str) -> tuple:
    """
    Take a test name and determine which package it references
    and the type of test it is.

    Paramters
    ---------
    name : str
        The name of the test. For example:
        "Check integrations / cef / cef: check / pipeline test: test-cef-event.json – cef.log"

    Returns
    -------
    tuple
        First element is the package name
        Second element is the package component
        Third element is the type of test

    Example
    -------
    >>> classify('io.jenkins.blueocean.service.embedded.rest.junit.BlueJUnitTestResult:aws.cloudtrail%3Ajunit%2Faws%2Fcloudtrail%2FCheck_integrations___aws___aws__check___pipeline_test__test_console_login_json_log') # noqa E205
    ('aws', 'cloudtrail', 'pipeline_test')
    """
    package, component = name.split("%2F")[1:3]
    test_type = name.split("___")[-1].split("__", maxsplit=1)[0].split('_')[0]
    return (package, component, test_type)


def validate_filter(func):
    """
    Decorator to verify that a valid filter was passed in

    Raises
    ------
    Exception
        If the passed in filter was not valid, a generalized Exception is
        raised
    """
    def wrapper(*args, **kwargs):
        if kwargs.get('type_filter') and kwargs['type_filter'] not in ('system', 'pipeline'):  # noqa E205
            raise Exception(
                    "Valid options for system_filter are: `system`, `pipeline`"
                    f" Function received: {kwargs['type_filter']}"
                            )
        func(*args, **kwargs)
        return func(*args, **kwargs)
    return wrapper


def dict_limit(data: dict, limit: int, high_pass: bool) -> dict:
    """
    Helper function to sort a dictionary by value and then select only
    up to a certain number of the sorted entries.

    Parameters
    ----------
    data : dict
        The dictionary to process
    limit : int
        If set, limit entries to the provided value. If `0` is passed, an empty
        dictionary is returned. If `-1` is passed, the original dictionary is
        returned unmodified.

    high_pass : bool
        If limit is set, this argument determines whether to return the lowest
        set of values or the highest. When False, only the lowest values up to
        to the number requested by `limit` will be returned. When True, only
        the highest values up to the numbe requested by `limit` will be
        returned.

    Returns
    -------
    dict
        A dictionary which contains the first N entries, as sorted by value
    """
    if limit == 0:
        return {}
    elif limit < 0:
        return data
    sort_list = sorted(
        data.items(),
        key=lambda x: x[1],
        reverse=high_pass
        )[:limit]

    filtered_dict = {}
    for pair in sort_list:
        filtered_dict[pair[0]] = pair[1]
    return filtered_dict


@validate_filter
def test_frequency(
    tests: list,
    packages: list,
    type_filter=None,
    limit=10,
    high_pass=False,
    include_untested=False
) -> dict:
    """
    Determine the frequency of tests

    Parameters
    ----------
    tests : list
        Test objects to analyze

    packages : list
        Packages to analyze

    str : type_filter
        If present, this calculates test frequency by type. Argument
        should be one of ['pipeline', 'system']. Default: None

    limit : int
        If set, limit entries to the provided value

    high_pass : bool
        If limit is set, this argument determines whether to return the lowest
        set of values or the highest. When False, only the lowest values up to
        to the number requested by `limit` will be returned. When True, only
        the highest values up to the numbe requested by `limit` will be
        returned.

    include_untested : bool
        If this flag is set to True, then packages for which no tests have been
        detected will be included in the final report. If it is False, then
        only tested packages will be included.

    Returns
    -------
    dict
        Dictionary describing test frequency. Example snippet:
        {'apache': 110,
        'auditd': 18,
        'aws': 340,
        'azure': 60,
        'cef': 14,
        ...
        }
    """
    frequency_map = {}
    # Initialize the map with the list of packages
    for package in packages:
        frequency_map[package] = 0

    # Bucket each test into the map
    for test in tests:
        if type_filter:
            if test.type == type_filter:
                frequency_map[test.package] += 1
        else:
            frequency_map[test.package] += 1

    if not include_untested:
        frequency_map = {k: v for (k, v) in frequency_map.items() if v > 0}

    frequency_map = dict_limit(frequency_map, limit, high_pass)

    return frequency_map


@validate_filter
def test_status(
        tests: list,
        type_filter=None,
        collate_by=None,
        limit=10,
        high_pass=False,
        include_untested=False) -> dict:  # noqa E205
    """
    Bucket tests by their status

    Parameters
    ----------
    tests : list
        Test objects to analyze

    str : type_filter
        If present, this calculates test frequency by type. Argument
        should be one of ['pipeline', 'system']. Default: None

    list : collate_by
        If set, this configures the value for a given key to simply
        contain the number of tests with the given condition(s). All
        items in the list will be included.

    limit : int
        Limit the number of entries returned. If collation is not set,
        this argument does nothing.

    high_pass : bool
        If limit is set, this argument determines whether to return the lowest
        set of values or the highest. When False, only the lowest values up to
        to the number requested by `limit` will be returned. When True, only
        the highest values up to the numbe requested by `limit` will be
        returned. If collation is not set, this argument does nothing.

    include_untested : bool
        If this flag is set to True, then packages for which no tests have been
        detected will be included in the final report. If it is False, then
        only tested packages will be included. If collation is not set, this argument
        does nothing.

    Returns
    -------
    dict
        A dictionary where tests are bucketed by their status
    """
    status_map = {}

    for test in tests:
        if test.package not in status_map:
            if collate_by:
                status_map[test.package] = 0
            else:
                status_map[test.package] = {
                    'PASSED': 0,
                    'FAILED': 0,
                    'ERROR': 0,
                    'UNKNOWN': 0
                    }
        if type_filter:
            if test.type == type_filter:
                if collate_by:
                    if test.result.lower() in [c.lower() for c in collate_by]:
                        status_map[test.package] += 1
                else:
                    status_map[test.package][test.result] += 1
        else:
            if collate_by:
                if test.result.lower() in [c.lower() for c in collate_by]:
                    status_map[test.package] += 1
            else:
                status_map[test.package][test.result] += 1

    if collate_by:
        if not include_untested:
            status_map = {k: v for (k, v) in status_map.items() if v > 0}
        status_map = dict_limit(status_map, limit, high_pass)

    return status_map


def jinja_tmpl():
    """
    Helper function to prepare and load the Jinja template

    Returns
    -------
    jinja.Template
        The main layout template from which all others inherit
    """
    env = jinja2.Environment(
            loader=jinja2.PackageLoader('report', 'templates'),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
            )
    return env.get_template('layout.html')


def render(template, freq, freq_system, freq_pipeline, freq_limit) -> str:
    """
    Take a template and its data and render it

    Parameters
    ----------
    template : Jinja2.Template
        Jina template to render

    freq : dict
        A dictionary containing a general frequency analysis

    freq_system : dict
        A diciontary containing a frequency analysis filtered by system tests

    freq_pipeline : dict
        A dictionary containing a frequency analysis filtered by pipeline tests

    freq_limit : int
        The number of individual entries that each report should be limited to

    Returns
    -------
    str
        The rendered HTML, ready for consumption
    """
    return template.render(
            test_frequency=freq,
            test_frequency_system=freq_system,
            test_frequency_pipeline=freq_pipeline,
            frequency_limit=freq_limit
            )


def send_html_email(
        subject: str,
        sender: str,
        to: str,
        content: str,
        smtp_user: str,
        smtp_pass: str,
        provider='gmail') -> None:
    """
    Send HTML email

    Parameters
    ----------
    subject : str
        Email subject

    sender : str
        Email sender

    to : str
        Email recepient

    content : str
        HTML content

    smtp_user : str
        Username to authenticate to SMTP server with

    smtp_pass : str
        Password to authenticate to SMTP server with

    provider : str
        Email provider. Supported providers: ['gmail']

    Raises
    ------
    Exception
        If the `provider` argument contains an unsupported provider, an exception is raised.
    """
    # construct email
    email = EmailMessage()
    email['Subject'] = subject
    email['From'] = sender
    email['To'] = ", ".join(to)
    email.set_content(content, subtype='html')

    # We just leave room in the future for other providers, as our infra needs
    # may shift underneath us
    if provider.lower() == 'gmail':
        logging.debug(f"Sending email to {to} from {sender} with subject: {subject}")  # noqa E205
        with SMTP('smtp.gmail.com', 587) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.send_message(email)
            s.quit()
    else:
        raise Exception("Must pass in supported email provider: "
                        f"{provider} is not supported")


if __name__ == "__main__":
    # Pre-flight setup of argument parsing and logging
    cli_args = gather_args()

    setup_logging(cli_args.verbose)

    # Begin main operations

    # Fetch tests from the Elasticsearch stats cluster
    logging.info("✨ Fetching test history from Elasticsearch")
    es_ = es_conn(cli_args.es_host, cli_args.es_user, cli_args.es_pass)
    es_response = gather_docs(es_, cli_args.timespan)

    # Fetch list of packages from GitHub
    logging.info("✨ Fetching list of packages")
    gh_ = gh_conn(cli_args.gh_token)
    gh_response = gather_gh_packages(gh_)

    es_tests = []
    for doc in es_response['hits']['hits']:
        es_tests.extend(extract_tests(doc))

    logging.info("🤔 Analyzing test frequency [overall]")
    freq = test_frequency(
        es_tests,
        gh_response,
        limit=cli_args.limit,
        include_untested=cli_args.include_untested
        )

    logging.info("🤔 Analyzing test frequency [system]")
    freq_system = test_frequency(
        es_tests,
        gh_response,
        type_filter='system',
        limit=cli_args.limit,
        include_untested=cli_args.include_untested
        )

    logging.info("🤔 Analyzing test frequency [pipeline]")
    freq_pipeline = test_frequency(
        es_tests,
        gh_response,
        type_filter='pipeline',
        limit=cli_args.limit,
        include_untested=cli_args.include_untested
        )

    logging.info("🤔 Analyzing test status")
    status = test_status(es_tests)

    tmpl = jinja_tmpl()

    if cli_args.output == "stdout":
        print(render(tmpl, freq, freq_system, freq_pipeline, cli_args.limit))
    elif cli_args.output == "email":
        html_out = render(
            tmpl,
            freq,
            freq_system,
            freq_pipeline,
            cli_args.limit
            )
        logging.info("📧 Sending email report")
        send_html_email(
            "Integrations test report",
            cli_args.smtp_user,
            cli_args.smtp_recipient,
            html_out,
            cli_args.smtp_user,
            cli_args.smtp_pass
        )

    logging.info("🏁 Done!")
