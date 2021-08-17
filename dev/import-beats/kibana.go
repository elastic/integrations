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
	"path/filepath"
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
	Version string   `json:"version"`
}

func newKibanaMigrator(hostPort string, username string, password string, skipKibana bool) *kibanaMigrator {
	return &kibanaMigrator{
		hostPort:   hostPort,
		username:   username,
		password:   password,
		skipKibana: skipKibana,
	}
}

func (km *kibanaMigrator) migrateDashboardFile(dashboardFile []byte, moduleName string, dataStreamNames []string) ([]byte, error) {
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
	dataStreamNames []string) (kibanaContent, error) {
	if kibanaMigrator.skipKibana {
		log.Printf("\tKibana migrator disabled, skipped (modulePath: %s)", modulePath)
		return kibanaContent{}, nil
	}

	moduleDashboardPath := filepath.Join(modulePath, "_meta", "kibana", "7", "dashboard")
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

	dashboardIDMap := make(map[string]string, 0)
	for _, moduleDashboard := range moduleDashboards {
		log.Printf("\tdashboard found: %s", moduleDashboard.Name())

		dashboardFilePath := filepath.Join(moduleDashboardPath, moduleDashboard.Name())
		extracted, idMap, err := extractDashboard(kibanaMigrator, dashboardFilePath, moduleName, dataStreamNames)
		if err != nil {
			return kibanaContent{}, errors.Wrapf(err, "converting dashboard")
		}

		for origID, newID := range idMap {
			dashboardIDMap[origID] = newID
		}

		for objectType, objects := range extracted {
			if _, ok := kibana.files[objectType]; !ok {
				kibana.files[objectType] = map[string][]byte{}
			}

			for k, v := range objects {
				kk := string(replaceBlacklistedWords([]byte(k)))
				kibana.files[objectType][kk] = v
			}
		}
	}

	// Make a pass over all asset files and replace dashboard links in them
	for objectType, files := range kibana.files {
		for filename, data := range files {
			for origID, newID := range dashboardIDMap {
				data = updateDashboardLinks(data, origID, newID)
				kibana.files[objectType][filename] = data
			}
		}
	}

	return kibana, nil
}

func extractDashboard(kibana *kibanaMigrator, path string, module string, dataStreams []string) (map[string]map[string][]byte, map[string]string, error) {
	dashboardFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "reading dashboard file failed (path: %s)", path)
	}

	if filepath.Ext(path) == ".ndjson" {
		return convertKibanaObjects(dashboardFile, module, dataStreams)
	}

	migrated, err := kibana.migrateDashboardFile(dashboardFile, module, dataStreams)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "migrating dashboard file failed (path: %s)", path)
	}

	return convertToKibanaObjects(migrated, module, dataStreams)
}

func convertToKibanaObjects(dashboardFile []byte, moduleName string, dataStreamNames []string) (map[string]map[string][]byte, map[string]string, error) {
	var documents kibanaDocuments

	err := json.Unmarshal(dashboardFile, &documents)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "unmarshalling migrated dashboard file failed")
	}

	return migrateKibanaObjects(documents.Objects, moduleName, dataStreamNames)
}

func convertKibanaObjects(dashboardFile []byte, moduleName string, dataStreamNames []string) (map[string]map[string][]byte, map[string]string, error) {
	var objects []mapStr

	decoder := json.NewDecoder(bytes.NewReader(dashboardFile))
	for decoder.More() {
		var object mapStr
		err := decoder.Decode(&object)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding object failed: %v", err)
		}
		objects = append(objects, object)
	}

	return migrateKibanaObjects(objects, moduleName, dataStreamNames)
}

func migrateKibanaObjects(objects []mapStr, moduleName string, dataStreamNames []string) (map[string]map[string][]byte, map[string]string, error) {
	extracted := make(map[string]map[string][]byte)
	dashboardIDMap := make(map[string]string)

	for _, object := range objects {
		err := object.delete("updated_at")
		if err != nil {
			return nil, nil, errors.Wrapf(err, "removing field updated_at failed")
		}

		err = object.delete("version")
		if err != nil {
			return nil, nil, errors.Wrapf(err, "removing field version failed")
		}

		object, err = decodeFields(object)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "decoding fields failed")
		}

		object, err = stripReferencesToEventModule(object, moduleName, dataStreamNames)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "stripping references to event module failed")
		}

		aType, err := object.getValue("type")
		if err != nil {
			return nil, nil, errors.Wrapf(err, "retrieving type failed")
		}

		id, err := object.getValue("id")
		if err != nil {
			return nil, nil, errors.Wrapf(err, "retrieving id failed")
		}

		origID, ok := id.(string)
		if !ok {
			return nil, nil, errors.New("expected id to be a string")
		}

		newID := updateObjectID(origID, moduleName)

		_, err = object.put("id", newID)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "putting new ID failed")
		}

		// Update any references to other objects in this object
		refs, err := object.getValue("references")
		if err != nil {
			return nil, nil, errors.Wrap(err, "retrieving references failed")
		}

		references, ok := refs.([]interface{})
		if !ok {
			return nil, nil, errors.New("expected references to be an array of objects")
		}

		for _, r := range references {
			ref, ok := r.(map[string]interface{})
			if !ok {
				return nil, nil, errors.New("expected reference to be an object")
			}

			reference := mapStr(ref)

			// Exclude index pattern references
			rt, err := reference.getValue("type")
			if err != nil {
				return nil, nil, errors.Wrap(err, "retrieving reference type failed")
			}
			refType, ok := rt.(string)
			if !ok {
				return nil, nil, errors.New("expected reference type to be a string")
			}

			if refType == "index-pattern" {
				continue
			}

			refID, err := reference.getValue("id")
			if err != nil {
				return nil, nil, errors.Wrapf(err, "retrieving reference id failed")
			}

			origRefID, ok := refID.(string)
			if !ok {
				return nil, nil, errors.New("expected reference id to be a string")
			}

			newRefID := updateObjectID(origRefID, moduleName)

			if _, err := reference.put("id", newRefID); err != nil {
				return nil, nil, errors.Wrapf(err, "putting new reference ID failed")
			}
		}

		data, err := json.MarshalIndent(object, "", "    ")
		if err != nil {
			return nil, nil, errors.Wrapf(err, "marshalling object failed")
		}

		data = replaceFieldEventDatasetWithDataStreamDataset(data)
		data = replaceBlacklistedWords(data)
		data = removeECSTextualSuffixes(data)
		err = verifyKibanaObjectConvertion(data)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Kibana object convertion failed")
		}

		if _, ok := extracted[aType.(string)]; !ok {
			extracted[aType.(string)] = map[string][]byte{}
		}

		dashboardIDMap[origID] = newID
		extracted[aType.(string)][newID+".json"] = data
	}

	return extracted, dashboardIDMap, nil
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

func stripReferencesToEventModule(object mapStr, moduleName string, dataStreamNames []string) (mapStr, error) {
	key := "attributes.kibanaSavedObjectMeta.searchSourceJSON.filter"
	object, err := stripReferencesToEventModuleInFilter(object, key, moduleName)
	if err != nil {
		return nil, errors.Wrapf(err, "stripping reference in searchSourceJSON.filter failed (moduleName: %s)", moduleName)
	}

	key = "attributes.kibanaSavedObjectMeta.searchSourceJSON.query"
	object, err = stripReferencesToEventModuleInQuery(object, key, moduleName, dataStreamNames)
	if err != nil {
		return nil, errors.Wrapf(err, "stripping reference in searchSourceJSON.query failed (moduleName: %s)", moduleName)
	}

	key = "attributes.visState.params.filter"
	object, err = stripReferencesToEventModuleInQuery(object, key, moduleName, dataStreamNames)
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

			_, err = filterObject.put("meta.value", fmt.Sprintf("{\"prefix\":{\"data_stream.dataset\":\"%s.\"}}", moduleName))
			if err != nil {
				return nil, errors.Wrapf(err, "setting meta.value failed")
			}

			err = filterObject.delete("meta.params")
			if err != nil {
				return nil, errors.Wrapf(err, "removing meta.params failed")
			}

			q := map[string]interface{}{
				"prefix": map[string]interface{}{
					"data_stream.dataset": moduleName + ".",
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

func stripReferencesToEventModuleInQuery(object mapStr, objectKey, moduleName string, dataStreamNames []string) (mapStr, error) {
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
		query = strings.ReplaceAll(query, "metricset.name:", fmt.Sprintf("data_stream.dataset:%s.", moduleName))
		query = strings.ReplaceAll(query, "fileset.name:", fmt.Sprintf("data_stream.dataset:%s.", moduleName))
		query = strings.TrimSpace(query)
		if strings.HasPrefix(query, "AND ") {
			query = query[4:]
		}

		_, err := object.put(queryKey, query)
		if err != nil {
			return nil, fmt.Errorf("replacing key '%s' failed: %v", queryKey, err)
		}
	} else if strings.Contains(query, "event.module:"+moduleName) {
		var eventDataStreams []string
		for _, dataStreamName := range dataStreamNames {
			eventDataStreams = append(eventDataStreams, fmt.Sprintf("data_stream.dataset:%s.%s", moduleName, dataStreamName))
		}

		value := " (" + strings.Join(eventDataStreams, " OR ") + ") "
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

func replaceFieldEventDatasetWithDataStreamDataset(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("event.dataset"), []byte("data_stream.dataset"))
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

func updateDashboardLinks(data []byte, origID, newID string) []byte {
	return bytes.ReplaceAll(data, []byte("#/dashboard/"+origID), []byte("#/dashboard/"+newID))
}

func removeECSTextualSuffixes(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte(" ECS"), []byte(""))
}

func updateObjectID(origID, moduleName string) string {
	// If object ID starts with the module name, make sure that module name is all lowercase
	// Else, prefix an all-lowercase module name to the object ID.
	newID := origID
	prefix := moduleName + "-"
	if strings.HasPrefix(strings.ToLower(newID), prefix) {
		newID = newID[len(prefix):]
	}
	newID = prefix + newID

	// If object ID ends with "-ecs", trim it off.
	ecsSuffix := "-ecs"
	if strings.HasSuffix(newID, "-ecs") {
		newID = strings.TrimSuffix(newID, ecsSuffix)
	}

	// Finally, if after all transformations if the new ID is the same as the
	// original one, to avoid a collision, we suffix "-pkg"
	if newID == origID {
		newID += "-pkg"
	}

	return newID
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
