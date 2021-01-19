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

See the following table for variables which can be set via environment variables:

|CLI Argument|Env variable|
|------------|------------|
|`--es-host` |IREPORT_ES_HOST|
|`--es-user` |IREPORT_ES_USER|
|`--es-pass` |IREPORT_ES_PASS|
|`--gh-token`|IREPORT_GH_TOKEN|
|`--smtp-recipient`|IREPORT_SMTP_RECIP|
|`--smtp-user`|IREPORT_SMTP_USER|
|`--smtp-pass`|IREPORT_SMTP_PASS|
|`--limit`|IREPORT_TEST_LIMIT|

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

In addition to Python tests, there are basic [BATS](https://github.com/sstephenson/bats) just to verify that the Docker image can be built without errors.

To run all tests:

```bash
❯ make test
Tests are in progress, please be patient
 ✓ Build image

1 test, 0 failures
========================================================================================================================================= test session starts =========================================================================================================================================
platform darwin -- Python 3.9.0, pytest-6.2.1, py-1.10.0, pluggy-0.13.1
rootdir: /Users/mp/devel/integrations/.ci/reporter
collected 51 items

tests/test_report.py ...................................................                                                                                                                                                                                                                        [100%]

========================================================================================================================================= 51 passed in 0.30s ==========================================================================================================================================
```

### Adding or modifying a report
#### Analyzers
Analyzers can take input pulled from data sources, such as the GitHub API or queries to an Elasticsearch cluster containing
test results and then analyze them to produce data structure.

Analyzers start with `test_` in `report.py` by convention. The current analyzers are designed to be somewhat flexible but if they not meeting one's needs, a new analyzer may be added. Currently, there is no fixed format for output but by convention, they all support
outputting a dictionary where the keys are tests and the values are integers representing some type of value about that
test which has been analyzed by the `test_` function. (This may be enforced in the future if there is a need, so it is
a good idea to try to support this if you can.)

#### Reports
Reports can either be directed to standard out or as an email via the use of the `--output` flag. All reports are written
using the [Jinja2 templating language](https://jinja.palletsprojects.com/en/2.11.x/templates/). Find the catalog of available
reports in the `/templates` directory from the root of this project. Currently template inheretance is not used but if there
is a need for it in the future, it may be added to simplifiy the development of additional reports.

### Logging

Pass `-v` to enable debug logging.

### Development and testing workflow

The easiest thing to do is just to execute `report.py` with the appropriate options and the `--output=stdout` flag is set, logging will be sent to standard error and the output will be sent to standard out. Therefore, a command such as the following
will produce results and open the results directly in Firefox:

```bash
> ./report.py > /tmp/out.html && /Applications/Firefox.app/Contents/MacOS/firefox-bin /tmp/out.html
``` 

## Deployment

This project contains a Docker file as well as a deployment manifest which can be used to deploy the application inside
a Kubenretes cluster. (This requires knowledge of the Elastic internal applications cluster which is not discussed here.)

If you require access to view or change the secrets, please contact the Observability Developer Productivity Team. 

## Getting help

🤖 This project was built and is maintained by the Observability Robots group at Elastic. 