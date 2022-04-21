#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys
import signal
import time

from operator import add
from datetime import datetime

from pyspark.sql import SparkSession

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: wordcount <file>", file=sys.stderr)
        sys.exit(-1)

    spark = SparkSession\
        .builder\
        .master(sys.argv[2])\
        .appName("PythonWordCount")\
        .getOrCreate()
    
    t_end = time.time() + 60 * 15

    # Run loop for 15 mins
    while time.time() < t_end:
      lines = spark.read.text(sys.argv[1]).rdd.map(lambda r: r[0])  
      counts = lines.flatMap(lambda x: x.split(' ')) \
                    .map(lambda x: (x, 1)) \
                    .reduceByKey(add)
      output = counts.collect()
      for (word, count) in output:
          print("%s: %i" % (word, count))

    spark.stop()
