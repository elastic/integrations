# Host Risk Score

The host risk score feature highlights risky hosts from within your environment. It utilizes a transform with a scripted metric aggregation to calculate host risk scores based on alerts that were generated within the past five days. The transform runs hourly to update the score as new alerts are generated.

Each rule’s contribution to the host risk score is based on the rule’s risk score (signal.rule.risk_score) and a time decay factor to reduce the impact of stale alerts. The risk score is calculated using a weighted sum where rules with higher time-corrected risk scores also have higher weights. Each host risk score is normalized to a scale of 0 to 100.

Specific host attributes can boost the final risk score. For example, alert activity on a server poses a greater risk than that on a laptop. Therefore, the host risk score is 1.5 times higher if the host is a server. This boosted score is finalized after calculating the weighted sum of the time-corrected risks.

https://www.elastic.co/guide/en/security/7.17/host-risk-score.html
