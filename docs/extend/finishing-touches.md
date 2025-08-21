---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/finishing-touches.html
---

# Finishing touches [finishing-touches]

## Words [_words]

Tips for manifest files:

* Descriptions of configuration options should be as short as possible.

    Remember to keep only the meaningful information about the configuration option.

    * Good candidates: references to the product configuration, accepted string values, explanation.
    * Bad candidates: Collect metrics from A, B, C, D,…​ X, Y, Z datasets.


* Descriptions should be human readable.

    Try to rephrase sentences like: Collect foo_Bar3 metrics, into Collect Foo Bar metrics.

* Descriptions should be easy to understand.

    Simplify sentences, don’t provide information about the input if not required.

    * Bad candidate: Collect application logs (log input)
    * Good candidates: Collect application logs, Collect standard logs for the application



## Add an icon [_add_an_icon]

The integration icons are displayed in different places in {{kib}}, hence it’s better to define custom icons to make the UI easier to navigate.


## Add screenshots [_add_screenshots]

The {{kib}} Integration Manager shows screenshots related to the integration. Screenshots include {{kib}} dashboards visualizing the metric and log data.


## Create a README file [_create_a_readme_file]

The README template is used to render the final README file, including exported fields. The template should be located in the `package/<integration-name>/_dev/build/docs/README.md`. The template will include guidance on the structure and content expected for the integration.

To see how to use template functions, for example {{fields "data-stream-name"}}, review the MySQL docs template. If the same data stream name is used in both metrics and logs, please add -metrics and -logs in the template. For example, ELB is a data stream for log and also a data stream for metrics. In README.md template, {{fields "elb_logs"}} and {{fields "elb_metrics"}} are used to separate them.


## Review artifacts [_review_artifacts]



## Define variable properties [define-variable-properties]

The variable properties customize visualization of configuration options in the {{kib}} UI. Make sure they’re defined in all manifest files.

```yaml
vars:
  - name: paths
    required: true <1>
    show_user: true <2>
    title: Access log paths <3>
    description: Paths to the apache access log file. <4>
    type: text <5>
    multi: true <6>
    hide_in_deployment_modes: <7>
      - agentless
    default:
      - /var/log/httpd/access.log*
```

1. option is required
2. don’t hide the configuration option (collapsed menu)
3. human readable variable name
4. variable description (may contain some details)
5. field type (according to the reference: text, password, bool, integer)
6. the field has multiple values
7. hides the variable in agentless mode (see [`hide_in_deployment_modes`](/extend/define-deployment-modes.md#hide_in_deployment_modes) for more information)
