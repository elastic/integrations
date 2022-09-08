# Recorded Future Integration

The Recorded Future integration fetches _risklists_ from the [Recorded Future API](https://api.recordedfuture.com/index.html).
It supports `domain`, `hash`, `ip` and `url` entities.

In order to use it you need to define the `entity` and `list` to fetch. Check with
Recorded Future for the available lists for each entity. To fetch indicators
from multiple entities, it's necessary to define one integration for each.

Alternatively, it's also possible to use the integration to fetch custom Fusion files
by supplying the URL to the CSV file as the _Custom_ _URL_ configuration option.

**NOTE:** For large risklist downloads, adjust the timeout setting so that the Agent has enough time to download and process the risklist.

{{event "threat"}}

{{fields "threat"}}
