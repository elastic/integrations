# Development notes

All copies of some files are identical. This should be maintained.

It is especially important for the `common_init.yml` and `common_host.yml`
pipeline definitions that are shared across many data streams.

To check whether there are multiple versions of each of these files, use the
following commands to list them with their MD5 hashes.

```
echo; find -name 'common_host.yml' | xargs md5sum | sort
echo; find -name 'common_init.yml' | xargs md5sum | sort
echo; find -name 'default_policy.json' | xargs md5sum | sort
echo; find -name 'docker-compose.yml' | xargs md5sum | sort
echo; find -name 'ecs-required.yml' | xargs md5sum | sort
echo; find -name 'filestream.yml.hbs' | xargs md5sum | sort
echo; find -name 'filestream.yml' | xargs md5sum | sort
echo; find -name 'is-transform-source-false.yml' | xargs md5sum | sort
echo; find -name 'is-transform-source-true.yml' | xargs md5sum | sort
echo; find -name 'test-default-config.yml' | xargs md5sum | sort
echo; find -name 'tychon-agent.yml' | xargs md5sum | sort
echo; find -wholename './elasticsearch/transform/*/manifest.yml' | xargs md5sum | sort
```

It is also important to keep the field definitions for each transform
destination index aligned with the field definitions for its source data
stream. (Although they will differ in `is-transform-source-*.yml` files, and
the source data streams do not need to explicitly define ECS fields.)

There are other files that have only minor differences between data streams.
When making a change to one data stream, consider whether there is a
corresponding change to make in other data streams.
