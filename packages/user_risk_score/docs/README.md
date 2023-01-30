# User Risk Score

The user risk score feature highlights risky usernames in your environment. It utilizes a transform with a scripted metric aggregation to calculate user risk scores based on alerts generated within the past 90 days. The transform runs hourly to update scores as new alerts are generated.

Each alert’s contribution to the user risk score is based on the alert’s risk score (signal.rule.risk_score). The risk score is calculated using a weighted sum where rules with higher time-corrected risk scores also have higher weights. Each risk score is normalized on a scale of 0 to 100.

# Installation

You can install the User Risk Score package via Management > Integrations > User Risk Score.

To inspect the installed assets, you can navigate to Stack Management > Data > Transforms.

Namely, the following transforms are installed with the User Risk Score package:


| Transform name                   | Purpose                                                    | Source index                             | Destination index                                  |
|----------------------------------|------------------------------------------------------------|------------------------------------------|----------------------------------------------------|
| user_risk_score.pivot_transform  | Calculates the User risk score                             | `.alerts-security.alerts-default`        | `.alerts-security.user-risk-score-[version]`       |
| user_risk_score.latest_transform | Surfaces the latest 90 days of the pivot transform results | `.alerts-security.user-risk-score.latest` | `.alerts-security.user-risk-score-latest-[version]` |

Note: This package assumes that `.alerts-security.alerts-default` exists on the cluster, which is generally true. However, in cases such as a brand-new cluster, the `.alerts-security.alerts-default` will not exist yet until the very first alert is triggered on the cluster. One solution would be to create a rule that would trigger an alert, and thus ensure the index exists.

# Additional Information

This package is an alternate way to the [User Risk Score](https://www.elastic.co/guide/en/security/current/user-risk-score.html) Elastic assets (transforms, ingest pipeline) that were originally installed via the Security App's Entity Analytics dashboard.

The notable differences is that this Integration package:

1. Only supports the default space, while the [Security App](https://www.elastic.co/guide/en/security/current/user-risk-score.html) supports other spaces.
2. The User Risk features in the Security App aren't currently backed by the data coming from this Integration package.


