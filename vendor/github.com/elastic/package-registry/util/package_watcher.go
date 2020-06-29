// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package util

import (
	"log"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/radovskyb/watcher"
)

const watcherPollingPeriod = 2 * time.Second

var (
	w *watcher.Watcher
)

func MustUsePackageWatcher(packagePaths []string) {
	log.Println("Use package watcher")

	var err error
	packageList, err = getPackagesFromFilesystem(packagePaths)
	if err != nil {
		log.Println(errors.Wrap(err, "watcher error: reading packages failed"))
	}

	w = watcher.New()
	w.SetMaxEvents(1)

	for _, p := range packagePaths {
		err = w.AddRecursive(p)
		if err != nil && !os.IsNotExist(err) {
			log.Fatal(errors.Wrapf(err, "watching directory failed (path: %s)", p))
		}
	}

	go w.Start(watcherPollingPeriod)

	go func() {
		for {
			select {
			case _, ok := <-w.Event:
				if !ok {
					log.Println("Package watcher is stopped")
					return // channel is closed
				}

				time.Sleep(watcherPollingPeriod) // reload at the end of watch frame
				log.Println("Reloading packages...")
				packageList, err = getPackagesFromFilesystem(packagePaths)
				if err != nil {
					log.Println(errors.Wrap(err, "watcher error: reading packages failed"))
				}
			case err, ok := <-w.Error:
				if !ok {
					log.Println("Package watcher is stopped")
					return // channel is closed
				}
				log.Println(errors.Wrap(err, "watcher error"))
			}
		}
	}()
}

func ClosePackageWatcher() {
	if !packageWatcherEnabled() {
		return
	}
	w.Close()
}

func packageWatcherEnabled() bool {
	return w != nil
}
