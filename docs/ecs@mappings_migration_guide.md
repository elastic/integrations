# ecs@mappings migration guide for integration developers

## History

In the initial stages, our approach involved individually specifying ECS fields within each package.

```yaml
- name: provider
  level: extended
  type: keyword
  ignore_above: 1024
  description: Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean.
```

As we progressed, the need for more efficient methodologies became apparent, prompting us to explore alternative strategies.
