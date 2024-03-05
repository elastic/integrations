// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
)

var (
	encodedFields = []string{
		"attributes.kibanaSavedObjectMeta.searchSourceJSON",
		"attributes.layerListJSON",
		"attributes.mapStateJSON",
		"attributes.optionsJSON",
		"attributes.panelsJSON",
		"attributes.uiStateJSON",
		"attributes.visState",
	}
)

type kibanaContent struct {
	files map[string]map[string][]byte
}

type kibanaMigrator struct {
	hostPort string
	username string
	password string

	skipKibana bool
}

type kibanaDocuments struct {
	Objects []mapStr `json:"objects"`
}

func newKibanaMigrator(hostPort string, username string, password string, skipKibana bool) *kibanaMigrator {
	return &kibanaMigrator{
		hostPort:   hostPort,
		username:   username,
		password:   password,
		skipKibana: skipKibana,
	}
}

func (km *kibanaMigrator) migrateDashboardFile(dashboardFile []byte, moduleName string, datasetNames []string) ([]byte, error) {
	dashboardFile, err := prepareDashboardFile(dashboardFile)
	if err != nil {
		return nil, errors.Wrapf(err, "preparing file failed")
	}

	request, err := http.NewRequest("POST",
		fmt.Sprintf("%s/api/kibana/dashboards/import?force=true", km.hostPort),
		bytes.NewReader(dashboardFile))
	if err != nil {
		return nil, errors.Wrapf(err, "creating POST request failed")
	}
	request.Header.Add("kbn-xsrf", "8.0.0")
	if km.username != "" {
		request.SetBasicAuth(km.username, km.password)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, errors.Wrapf(err, "making POST request to Kibana failed")
	}
	defer response.Body.Close()

	saved, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "reading saved object failed")
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("making POST request failed: %s", string(saved))
	}
	return saved, nil
}

func prepareDashboardFile(dashboardFile []byte) ([]byte, error) {
	var documents kibanaDocuments

	// Rename indices (metricbeat, filebeat)
	dashboardFile = bytes.ReplaceAll(dashboardFile, []byte(`metricbeat-*`), []byte(`metrics-*`))
	dashboardFile = bytes.ReplaceAll(dashboardFile, []byte(`filebeat-*`), []byte(`logs-*`))

	err := json.Unmarshal(dashboardFile, &documents)
	if err != nil {
		return nil, errors.Wrapf(err, "unmarshalling dashboard file failed")
	}

	for i, object := range documents.Objects {
		object, err = encodeFields(object)
		if err != nil {
			return nil, errors.Wrapf(err, "encoding fields failed")
		}
		documents.Objects[i] = object
	}

	data, err := json.Marshal(&documents)
	if err != nil {
		return nil, errors.Wrapf(err, "marshalling dashboard file failed")
	}
	return data, nil
}

func encodeFields(ms mapStr) (mapStr, error) {
	for _, field := range encodedFields {
		v, err := ms.getValue(field)
		if err == errKeyNotFound {
			continue
		} else if err != nil {
			return mapStr{}, errors.Wrapf(err, "retrieving value failed (key: %s)", field)
		}

		_, isString := v.(string)
		if isString {
			continue
		}

		ve, err := json.Marshal(v)
		if err != nil {
			return mapStr{}, errors.Wrapf(err, "marshalling value failed (key: %s)", field)
		}

		_, err = ms.put(field, string(ve))
		if err != nil {
			return mapStr{}, errors.Wrapf(err, "putting value failed (key: %s)", field)
		}
	}
	return ms, nil
}

func createKibanaContent(kibanaMigrator *kibanaMigrator, modulePath string, moduleName string,
	datasetNames []string) (kibanaContent, error) {
	if kibanaMigrator.skipKibana {
		log.Printf("\tKibana migrator disabled, skipped (modulePath: %s)", modulePath)
		return kibanaContent{}, nil
	}

	moduleDashboardPath := path.Join(modulePath, "_meta", "kibana", "7", "dashboard")
	moduleDashboards, err := ioutil.ReadDir(moduleDashboardPath)
	if os.IsNotExist(err) {
		log.Printf("\tno dashboards present, skipped (modulePath: %s)", modulePath)
		return kibanaContent{}, nil
	}
	if err != nil {
		return kibanaContent{}, errors.Wrapf(err, "reading module dashboard directory failed (path: %s)",
			moduleDashboardPath)
	}

	kibana := kibanaContent{
		files: map[string]map[string][]byte{},
	}
	for _, moduleDashboard := range moduleDashboards {
		log.Printf("\tdashboard found: %s", moduleDashboard.Name())

		dashboardFilePath := path.Join(moduleDashboardPath, moduleDashboard.Name())
		dashboardFile, err := ioutil.ReadFile(dashboardFilePath)
		if err != nil {
			return kibanaContent{}, errors.Wrapf(err, "reading dashboard file failed (path: %s)",
				dashboardFilePath)
		}

		migrated, err := kibanaMigrator.migrateDashboardFile(dashboardFile, moduleName, datasetNames)
		if err != nil {
			return kibanaContent{}, errors.Wrapf(err, "migrating dashboard file failed (path: %s)",
				dashboardFilePath)
		}

		extracted, err := convertToKibanaObjects(migrated, moduleName, datasetNames)
		if err != nil {
			return kibanaContent{}, errors.Wrapf(err, "extracting kibana dashboards failed")
		}

		for objectType, objects := range extracted {
			if _, ok := kibana.files[objectType]; !ok {
				kibana.files[objectType] = map[string][]byte{}
			}

			for k, v := range objects {
				kibana.files[objectType][k] = v
			}
		}
	}
	return kibana, nil
}

func convertToKibanaObjects(dashboardFile []byte, moduleName string, datasetNames []string) (map[string]map[string][]byte, error) {
	var documents kibanaDocuments

	err := json.Unmarshal(dashboardFile, &documents)
	if err != nil {
		return nil, errors.Wrapf(err, "unmarshalling migrated dashboard file failed")
	}

	extracted := map[string]map[string][]byte{}
	for _, object := range documents.Objects {
		err = object.delete("updated_at")
		if err != nil {
			return nil, errors.Wrapf(err, "removing field updated_at failed")
		}

		err = object.delete("version")
		if err != nil {
			return nil, errors.Wrapf(err, "removing field version failed")
		}

		object, err = decodeFields(object)
		if err != nil {
			return nil, errors.Wrapf(err, "decoding fields failed")
		}

		object, err = stripReferencesToEventModule(object, moduleName, datasetNames)
		if err != nil {
			return nil, errors.Wrapf(err, "stripping references to event module failed")
		}

		aType, err := object.getValue("type")
		if err != nil {
			return nil, errors.Wrapf(err, "retrieving type failed")
		}

		data, err := json.MarshalIndent(object, "", "    ")
		if err != nil {
			return nil, errors.Wrapf(err, "marshalling object failed")
		}

		data = replaceBlacklistedWords(
			replaceFieldEventDatasetWithStreamDataset(
				data))

		err = verifyKibanaObjectConvertion(data)
		if err != nil {
			return nil, errors.Wrapf(err, "Kibana object convertion failed")
		}

		id, err := object.getValue("id")
		if err != nil {
			return nil, errors.Wrapf(err, "retrieving id failed")
		}

		if _, ok := extracted[aType.(string)]; !ok {
			extracted[aType.(string)] = map[string][]byte{}
		}
		extracted[aType.(string)][id.(string)+".json"] = data
	}

	return extracted, nil
}

func decodeFields(ms mapStr) (mapStr, error) {
	for _, field := range encodedFields {
		v, err := ms.getValue(field)
		if err == errKeyNotFound {
			continue
		} else if err != nil {
			return nil, errors.Wrapf(err, "retrieving value failed (key: %s)", field)
		}

		var target interface{}
		var vd mapStr
		vStr := v.(string)
		err = json.Unmarshal([]byte(vStr), &vd)
		if err != nil {
			var vda []mapStr
			err = json.Unmarshal([]byte(vStr), &vda)
			if err != nil {
				return nil, errors.Wrapf(err, "unmarshalling value failed (key: %s)", field)
			}
			target = vda
		} else {
			target = vd
		}

		_, err = ms.put(field, target)
		if err != nil {
			return nil, errors.Wrapf(err, "putting value failed (key: %s)", field)
		}
	}
	return ms, nil
}

func stripReferencesToEventModule(object mapStr, moduleName string, datasetNames []string) (mapStr, error) {
	key := "attributes.kibanaSavedObjectMeta.searchSourceJSON.filter"
	object, err := stripReferencesToEventModuleInFilter(object, key, moduleName)
	if err != nil {
		return nil, errors.Wrapf(err, "stripping reference in searchSourceJSON.filter failed (moduleName: %s)", moduleName)
	}

	key = "attributes.kibanaSavedObjectMeta.searchSourceJSON.query"
	object, err = stripReferencesToEventModuleInQuery(object, key, moduleName, datasetNames)
	if err != nil {
		return nil, errors.Wrapf(err, "stripping reference in searchSourceJSON.query failed (moduleName: %s)", moduleName)
	}

	key = "attributes.visState.params.filter"
	object, err = stripReferencesToEventModuleInQuery(object, key, moduleName, datasetNames)
	if err != nil {
		return nil, errors.Wrapf(err, "stripping reference in visState failed (moduleName: %s)", moduleName)
	}

	return object, nil
}

func stripReferencesToEventModuleInFilter(object mapStr, filterKey, moduleName string) (mapStr, error) {
	filterValue, err := object.getValue(filterKey)
	if err != nil && err != errKeyNotFound {
		return nil, fmt.Errorf("retrieving key '%s' failed: %v", filterKey, err)
	} else if err == errKeyNotFound {
		return object, nil // nothing to adjust
	}

	filters, ok := filterValue.([]interface{})
	if !ok {
		return object, nil // not an array, ignoring
	}
	if len(filters) == 0 {
		return object, nil // empty array, ignoring
	}

	var updatedFilters []mapStr
	for _, fi := range filters {
		filterObject, err := toMapStr(fi)
		if err != nil {
			return nil, errors.Wrapf(err, "converting to mapstr failed")
		}

		metaKeyObject, err := filterObject.getValue("meta.key")
		if err != nil {
			return nil, errors.Wrapf(err, "retrieving meta.key failed")
		}

		metaKey, ok := metaKeyObject.(string)
		if ok && metaKey == "event.module" {
			_, err = filterObject.put("meta.key", "query")
			if err != nil {
				return nil, errors.Wrapf(err, "setting meta.key failed")
			}

			_, err = filterObject.put("meta.type", "custom")
			if err != nil {
				return nil, errors.Wrapf(err, "setting meta.type failed")
			}

			_, err = filterObject.put("meta.value", fmt.Sprintf("{\"match_phrase_prefix\":{\"stream.dataset\":{\"query\":\"%s.\"}}}", moduleName))
			if err != nil {
				return nil, errors.Wrapf(err, "setting meta.value failed")
			}

			err = filterObject.delete("meta.params")
			if err != nil {
				return nil, errors.Wrapf(err, "removing meta.params failed")
			}

			q := map[string]interface{}{
				"match_phrase_prefix": map[string]interface{}{
					"stream.dataset": map[string]interface{}{
						"query": moduleName + ".",
					},
				},
			}
			_, err = filterObject.put("query", q)
			if err != nil {
				return nil, errors.Wrapf(err, "setting query failed")
			}
		}
		updatedFilters = append(updatedFilters, filterObject)
	}

	_, err = object.put(filterKey, updatedFilters)
	if err != nil {
		return nil, errors.Wrapf(err, "replacing filters failed (moduleName: %s)", moduleName)
	}
	return object, nil
}

func stripReferencesToEventModuleInQuery(object mapStr, objectKey, moduleName string, datasetNames []string) (mapStr, error) {
	objectValue, err := object.getValue(objectKey)
	if _, ok := objectValue.(map[string]interface{}); !ok {
		return object, nil // not a map object
	}

	languageKey := objectKey + ".language"
	queryKey := objectKey + ".query"

	queryValue, err := object.getValue(queryKey)
	if err != nil && err != errKeyNotFound {
		return nil, fmt.Errorf("retrieving key '%s' failed: %v", queryKey, err)
	} else if err == errKeyNotFound {
		return object, nil // nothing to adjust
	}

	query, ok := queryValue.(string)
	if !ok {
		return object, nil // complex query (not a simple string)
	}
	if query == "" {
		return object, nil // empty query field
	}

	query = strings.ReplaceAll(query, ": ", ":")
	query = strings.ReplaceAll(query, " :", ":")
	query = strings.ReplaceAll(query, `"`, "")
	if strings.Contains(query, "event.module:"+moduleName) && (strings.Contains(query, "metricset.name:") || strings.Contains(query, "fileset.name:")) {
		query = strings.ReplaceAll(query, "event.module:"+moduleName, "")
		query = strings.ReplaceAll(query, "metricset.name:", fmt.Sprintf("stream.dataset:%s.", moduleName))
		query = strings.ReplaceAll(query, "fileset.name:", fmt.Sprintf("stream.dataset:%s.", moduleName))
		query = strings.TrimSpace(query)
		if strings.HasPrefix(query, "AND ") {
			query = query[4:]
		}

		_, err := object.put(queryKey, query)
		if err != nil {
			return nil, fmt.Errorf("replacing key '%s' failed: %v", queryKey, err)
		}
	} else if strings.Contains(query, "event.module:"+moduleName) {
		var eventDatasets []string
		for _, datasetName := range datasetNames {
			eventDatasets = append(eventDatasets, fmt.Sprintf("stream.dataset:%s.%s", moduleName, datasetName))
		}

		value := " (" + strings.Join(eventDatasets, " OR ") + ") "
		query = strings.ReplaceAll(query, "event.module:"+moduleName, value)
		query = strings.TrimSpace(query)

		_, err := object.put(queryKey, query)
		if err != nil {
			return nil, fmt.Errorf("replacing key '%s' failed: %v", queryKey, err)
		}

		_, err = object.put(languageKey, "kuery")
		if err != nil {
			return nil, fmt.Errorf("replacing key '%s' failed: %v", languageKey, err)
		}
	}
	return object, nil
}

func replaceFieldEventDatasetWithStreamDataset(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("event.dataset"), []byte("stream.dataset"))
}

func replaceBlacklistedWords(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("Metricbeat"), []byte("Metrics"))
	data = bytes.ReplaceAll(data, []byte("metricbeat"), []byte("metrics"))
	data = bytes.ReplaceAll(data, []byte("Filebeat"), []byte("Logs"))
	data = bytes.ReplaceAll(data, []byte("filebeat"), []byte("logs"))
	data = bytes.ReplaceAll(data, []byte("Module"), []byte("Integration"))
	data = bytes.ReplaceAll(data, []byte("module"), []byte("integration"))
	return data
}

func verifyKibanaObjectConvertion(data []byte) error {
	i := bytes.Index(data, []byte("event.module"))
	if i > 0 {
		return fmt.Errorf("event.module spotted at pos. %d", i)
	}

	i = bytes.Index(data, []byte("event.dataset"))
	if i > 0 {
		return fmt.Errorf("event.dataset spotted at pos. %d", i)
	}
	return nil
}
