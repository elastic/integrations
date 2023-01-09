# User Risk Score

The user risk score feature highlights risky usernames in your environment. It utilizes a transform with a scripted metric aggregation to calculate user risk scores based on alerts generated within the past 90 days. The transform runs hourly to update scores as new alerts are generated.

Each alert’s contribution to the user risk score is based on the alert’s risk score (signal.rule.risk_score). The risk score is calculated using a weighted sum where rules with higher time-corrected risk scores also have higher weights. Each risk score is normalized on a scale of 0 to 100.