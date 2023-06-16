var StatsD = require('node-statsd'),
  client = new StatsD({host: "elastic-package-stack-elastic-agent-1", port: 8125})

function statsd_Client() {
  // Timing: sends a timing command with the specified milliseconds
  client.timing('response_time', 42);

  // Increment: Increments a stat by a value (default is 1)
  client.increment('counter');

  // Decrement: Decrements a stat by a value (default is -1)
  client.decrement('counter');

  // Histogram: send data for histogram stat
  client.histogram('histogram', 42);

  // Gauge: Gauge a stat by a specified amount
  client.gauge('gauge', 123.45);

  // Set: Counts unique occurrences of a stat (alias of unique)
  client.set('unique', 'bar');
  client.unique('unique', 'stacked');

  // Sampling, this will sample 25% of the time the StatsD Daemon will compensate for sampling
  client.increment('counter', 1, 0.25);

  // Tags, this will add user-defined tags to the data
  client.histogram('histogram', 42, ['system', 'stats']);

  // Using the callback
  client.set(['system', 'stats'], 42, function (error, bytes) {
    //this only gets called once after all messages have been sent
    if (error) {
      console.error('Oh noes! There was an error:', error);
    } else {
      console.log('Successfully sent', bytes, 'bytes');
    }
  });

  // Sampling, tags and callback are optional and could be used in any combination
  client.histogram('histogram', 42, 0.25); // 25% Sample Rate
  client.histogram('histogram', 42, ['tag']); // User-defined tag
  client.histogram('histogram', 42); // Callback
  client.histogram('histogram', 42, 0.25, ['tag']);
  client.histogram('histogram', 42, 0.25);
  client.histogram('histogram', 42, ['tag']);
  client.histogram('histogram', 42, 0.25, ['tag']);
}

for (let i = 1; i < 100; i++) {
  setTimeout(statsd_Client, i * 3000);
}