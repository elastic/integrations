# Integrations Test Reporter

The Integrations Test Reporter is a lightweight application which can generate reports on testing
for packages which are present in the [Integrations Repo](https://github.com/elastic/integrations).

## Requirements

This application was developed with Python 3.9.1, however, all versions of Python 3 are likely to work.
Python 2 is deprecated and is not a supported interpreter for this application.

## Configuration

This application can be configured in one of two ways. The full list of options can be seen by running
`./report.py -h`. Certain configuration variables may be set either via the command-line or via the
command-line option. In case both are present, the CLI option should take prescedence.

```
usage: report.py [-h] [-v] [--timespan TIMESPAN] --es-host ES_HOST --es-user ES_USER --es-pass ES_PASS --gh-token GH_TOKEN --smtp-recipient SMTP_RECIPIENT [--smtp-provider {gmail}] --smtp-user SMTP_USER --smtp-pass SMTP_PASS [--include-untested] [--limit LIMIT] [--output {email,stdout}]

Generate Integrations test report.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Run with increased logging. Useful for development and debugging.
  --timespan TIMESPAN   The length of time to search back through for tests to be included in this report. Pass with a suffix of h (hours), d (days), m (months), or y (years). Ex: `--history=10D` to gather history for the previous 10 days.
  --gh-token GH_TOKEN   GitHub token which has read access the elastic/integrations repo
  --include-untested    Include packages which are present in the repo but for which no tests have been found
  --limit LIMIT         Limit the number of tests displayed in reports
  --output {email,stdout}
                        Where should we send the generated HTML

Elasticsearch:
  --es-host ES_HOST     The URL of the Elasticsearch cluster which contains test results to be parsed. Can also be set with ES_HOST in the environment
  --es-user ES_USER     The username to use to authenticate to the Elasticsearch cluster which contains test results to be parsed. Can also be set with ES_USER in the environment
  --es-pass ES_PASS     The username to use to authenticate to the Elasticsearch cluster which contains test results to be parsed. Can also be set with ES_USER in the environment

Email:
  Configuration for SMTP mailer

  --smtp-recipient SMTP_RECIPIENT
                        SMTP recipient. (Can be passed multiple times.)
  --smtp-provider {gmail}
                        SMTP provider to use
  --smtp-user SMTP_USER
                        SMTP username to authenticate with
  --smtp-pass SMTP_PASS
                        SMTP password to authenticate with
```

## Development

### Testing

Tests are written using [Pytest](https://www.pytest.org). Excecute them by running `pytest` from the root of this project:

```bash
❯ pytest
================================================================================================================= test session starts =================================================================================================================
platform darwin -- Python 3.9.0, pytest-6.2.1, py-1.10.0, pluggy-0.13.1
rootdir: /Users/mp/devel/integrations/.ci/reporter
collected 51 items                                                                                                                                                                                                                                    

tests/test_report.py ...................................................                                                                                                                                                                        [100%]

================================================================================================================= 51 passed in 0.29s ==================================================================================================================
```

Tests are entirely self-contained and do not require network access or any Pytest plugins.

### Deployment

This project contains a Docker file. The recommended configuration is to deploy into a system which can run the container on a schedule.
