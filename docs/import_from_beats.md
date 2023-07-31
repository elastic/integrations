# Import from Beats modules

The import procedure heavily uses on the _import-beats_ script. If you are interested how does it work internally,
feel free to review the script's [README](https://github.com/elastic/integrations/tree/main/dev/import-beats/README.md).

1. Create an issue in the [integrations](https://github.com/elastic/integrations) to track ongoing progress with
    the integration (especially manual changes).

    Focus on the one particular product (e.g. MySQL, ActiveMQ) you would like to integrate with.
    Use this issue to mention every manual change that has been applied. It will help in adjusting the `import-beats`
    script and reviewing the integration.

2. Prepare the developer environment:
    1. Clone/refresh the following repositories:
        * https://github.com/elastic/beats
        * https://github.com/elastic/ecs
        * https://github.com/elastic/eui
        * https://github.com/elastic/kibana

       Make sure you don't have any manual changes applied as they will reflect on the integration.
    2. Clone/refresh the Elastic Integrations to always use the latest version of the script:
        * https://github.com/elastic/integrations
    3. Make sure you've the `mage` tool installed:
        ```bash
       $ go get -u -d github.com/magefile/mage
       ```
3. Use the `elastic-package stack up -v -d` command to boot up required dependencies:
    1. Elasticseach instance:
        * Kibana's dependency
    2. Kibana instance:
        * used to migrate dashboards, if not available, you can skip the generation (`SKIP_KIBANA=true`)

    _Hint_. There is the `elastic-package` cheat sheet available [here](https://github.com/elastic/integrations/blob/main/testing/environments/README.md).

4. Create a new branch for the integration in `integrations` repository (diverge from main).
5. Run the command: `mage ImportBeats` to start the import process (note that the import script assumes the projects checked out in step 2 are at `../{project-name}`).

    The outcome of running the `import-beats` script is directory with refreshed and updated integrations.

    It will take a while to finish, but the console output should be updated frequently to track the progress.
    The command should terminate with an exit code of 0. If it doesn't, please open an issue.

    Generated packages are stored by default in the `packages` directory. Generally, the import process
    updates all of the integrations, so don't be surprised if you notice updates to multiple integrations, including
    the one you're currently working on (e.g. `packages/foobarbaz`). You can either commit these changes
    or leave them for later.

    If you want to select a subgroup of packages, set the environment variable `PACKAGES` (comma-delimited list):

    ```bash
   $ PACKAGES=aws,cisco mage ImportBeats
    ```
