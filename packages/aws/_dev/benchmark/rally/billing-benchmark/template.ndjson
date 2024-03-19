{{- $currency := generate "aws.billing.currency" }}
{{- $groupBy := generate "aws.billing.group_definition.key" }}
{{- $period := generate "metricset.period" }}
{{- $cloudId := generate "cloud.account.id" }}
{{- $cloudRegion := generate "cloud.region" }}
{{- $timestamp := generate "timestamp" }}
{
    "@timestamp": "{{$timestamp.Format "2006-01-02T15:04:05.999999Z07:00"}}",
    "cloud": {
        "provider": "aws",
        "region": "{{$cloudRegion}}",
        "account": {
            "id": "{{$cloudId}}",
            "name": "{{generate "cloud.account.name"}}"
        }
    },
    "event": {
        "dataset": "aws.billing",
        "module": "aws",
        "duration": {{generate "event.duration"}}
    },
    "metricset": {
        "name": "billing",
        "period": {{$period}}
    },
    "ecs": {
        "version": "8.2.0"
    },
    "aws": {
        "billing": {
{{- if eq $groupBy "" }}
            "Currency": "{{$currency}}",
            "EstimatedCharges": {{generate "aws.billing.EstimatedCharges"}},
            "ServiceName": "{{generate "aws.billing.ServiceName"}}"
{{- else }}
{{- $sd := generate "aws.billing.start_date" }}
            "start_date": "{{ $sd.Format "2006-01-02T15:04:05.999999Z07:00" }}",
            "end_date": "{{ $sd | date_modify (print "+" $period "s") | date "2006-01-02T15:04:05.999999Z07:00" }}",
            "AmortizedCost": {
                "amount": {{printf "%.2f" (generate "aws.billing.AmortizedCost.amount")}},
                "unit": "{{$currency}}"
            },
            "BlendedCost": {
                "amount": {{printf "%.2f" (generate "aws.billing.BlendedCost.amount")}},
                "unit": "{{$currency}}"
            },
            "NormalizedUsageAmount": {
                "amount": {{generate "aws.billing.NormalizedUsageAmount.amount"}},
                "unit": "N/A"
            },
            "UnblendedCost": {
                "amount": {{printf "%.2f" (generate "aws.billing.UnblendedCost.amount")}},
                "unit": "{{$currency}}"
            },
            "UsageQuantity": {
                "amount": {{generate "aws.billing.UsageQuantity.amount"}},
                "unit": "N/A"
            },
            "group_definition": {
              "key": "{{$groupBy}}",
              "type": "{{generate "aws.billing.group_definition.type"}}"
            },
            "group_by": {
{{- if eq $groupBy "AZ"}}
              "AZ": "{{awsAZFromRegion $cloudRegion}}"
{{- else if eq $groupBy "INSTANCE_TYPE"}}
              "INSTANCE_TYPE": "{{generate "aws.billing.group_by.INSTANCE_TYPE"}}"
{{- else if eq $groupBy "SERVICE"}}
              "SERVICE": "{{generate "aws.billing.group_by.SERVICE"}}"
{{- else if eq $groupBy "LINKED_ACCOUNT"}}
              "LINKED_ACCOUNT": "{{$cloudId}}"
{{- end}}
            }
{{- end}}
        }
    },
    "service": {
        "type": "aws"
    },
    "agent": {
        "id": "{{generate "agent.id"}}",
        "name": "{{generate "agent.name"}}",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "{{generate "agent.ephemeral_id"}}"
    }
}
