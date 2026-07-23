// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jimlambrt/gldap"
)

const (
	ldapPort = 10389
	httpPort = 8080

	bindUser = "cn=admin,dc=testserver,dc=local"
	bindPass = "password"

	bindUserSpecial = `TESTSERVER\admin#special`
	bindPassSpecial = `p@ss:word&"quotes'` // YAML-special characters

	baseDN = "DC=testserver,DC=local"
)

// entry holds the attributes for a single LDAP directory entry.
type entry struct {
	dn    string
	attrs map[string][]string
}

var (
	// Groups with members — used for group resolution.
	groupDomainUsers = entry{
		dn: "CN=Domain Users,CN=Users,DC=testserver,DC=local",
		attrs: map[string][]string{
			"cn":                     {"Domain Users"},
			"description":            {"All domain users"},
			"distinguishedName":      {"CN=Domain Users,CN=Users,DC=testserver,DC=local"},
			"groupType":              {"-2147483646"},
			"instanceType":           {"4"},
			"isCriticalSystemObject": {"TRUE"},
			"member":                 {"CN=Administrator,CN=Users,DC=testserver,DC=local"},
			"name":                   {"Domain Users"},
			"objectCategory":         {"CN=Group,CN=Schema,CN=Configuration,DC=testserver,DC=local"},
			"objectClass":            {"top", "group"},
			"objectGUID":             {string(makeGUID(0x01))},
			"objectSid":              {string(makeSID(513))},
			"sAMAccountName":         {"Domain Users"},
			"sAMAccountType":         {"268435456"},
			"uSNChanged":             {"12345"},
			"uSNCreated":             {"12340"},
			"whenChanged":            {"20240122063740.0Z"},
			"whenCreated":            {"20240122063740.0Z"},
			"dSCorePropagationData":  {"20240122063740.0Z"},
			"showInAdvancedViewOnly": {"FALSE"},
		},
	}
	groupDomainAdmins = entry{
		dn: "CN=Domain Admins,CN=Users,DC=testserver,DC=local",
		attrs: map[string][]string{
			"adminCount":             {"1"},
			"cn":                     {"Domain Admins"},
			"description":            {"Designated administrators of the domain"},
			"distinguishedName":      {"CN=Domain Admins,CN=Users,DC=testserver,DC=local"},
			"groupType":              {"-2147483646"},
			"instanceType":           {"4"},
			"isCriticalSystemObject": {"TRUE"},
			"member":                 {"CN=Administrator,CN=Users,DC=testserver,DC=local"},
			"memberOf":               {"CN=Domain Users,CN=Users,DC=testserver,DC=local"},
			"name":                   {"Domain Admins"},
			"objectCategory":         {"CN=Group,CN=Schema,CN=Configuration,DC=testserver,DC=local"},
			"objectClass":            {"top", "group"},
			"objectGUID":             {string(makeGUID(0x02))},
			"objectSid":              {string(makeSID(512))},
			"sAMAccountName":         {"Domain Admins"},
			"sAMAccountType":         {"268435456"},
			"uSNChanged":             {"12770"},
			"uSNCreated":             {"12345"},
			"whenChanged":            {"20240122065250.0Z"},
			"whenCreated":            {"20240122063740.0Z"},
			"dSCorePropagationData":  {"20240122063740.0Z"},
		},
	}
	groupDomainComputers = entry{
		dn: "CN=Domain Computers,CN=Users,DC=testserver,DC=local",
		attrs: map[string][]string{
			"cn":                     {"Domain Computers"},
			"description":            {"All workstations and servers joined to the domain"},
			"distinguishedName":      {"CN=Domain Computers,CN=Users,DC=testserver,DC=local"},
			"groupType":              {"-2147483646"},
			"instanceType":           {"4"},
			"isCriticalSystemObject": {"TRUE"},
			"member":                 {"CN=WORKSTATION-01,CN=Computers,DC=testserver,DC=local"},
			"name":                   {"Domain Computers"},
			"objectCategory":         {"CN=Group,CN=Schema,CN=Configuration,DC=testserver,DC=local"},
			"objectClass":            {"top", "group"},
			"objectGUID":             {string(makeGUID(0x03))},
			"objectSid":              {string(makeSID(515))},
			"sAMAccountName":         {"Domain Computers"},
			"sAMAccountType":         {"268435456"},
			"uSNChanged":             {"12350"},
			"uSNCreated":             {"12342"},
			"whenChanged":            {"20240122063740.0Z"},
			"whenCreated":            {"20240122063740.0Z"},
			"dSCorePropagationData":  {"20240122063740.0Z"},
		},
	}

	// Empty groups — no member attribute.
	groupDecommissioned = entry{
		dn: "CN=Decommissioned,CN=Users,DC=testserver,DC=local",
		attrs: map[string][]string{
			"cn":                    {"Decommissioned"},
			"description":           {"Decommissioned accounts"},
			"distinguishedName":     {"CN=Decommissioned,CN=Users,DC=testserver,DC=local"},
			"groupType":             {"-2147483646"},
			"instanceType":          {"4"},
			"name":                  {"Decommissioned"},
			"objectCategory":        {"CN=Group,CN=Schema,CN=Configuration,DC=testserver,DC=local"},
			"objectClass":           {"top", "group"},
			"objectGUID":            {string(makeGUID(0x10))},
			"objectSid":             {string(makeSID(1101))},
			"sAMAccountName":        {"Decommissioned"},
			"sAMAccountType":        {"268435456"},
			"uSNChanged":            {"13000"},
			"uSNCreated":            {"13000"},
			"whenChanged":           {"20240327043009.0Z"},
			"whenCreated":           {"20240122063740.0Z"},
			"dSCorePropagationData": {"20240122063740.0Z"},
		},
	}
	groupContractors = entry{
		dn: "CN=Contractors,CN=Users,DC=testserver,DC=local",
		attrs: map[string][]string{
			"cn":                    {"Contractors"},
			"description":           {"External contractors"},
			"distinguishedName":     {"CN=Contractors,CN=Users,DC=testserver,DC=local"},
			"groupType":             {"-2147483646"},
			"instanceType":          {"4"},
			"name":                  {"Contractors"},
			"objectCategory":        {"CN=Group,CN=Schema,CN=Configuration,DC=testserver,DC=local"},
			"objectClass":           {"top", "group"},
			"objectGUID":            {string(makeGUID(0x11))},
			"objectSid":             {string(makeSID(1102))},
			"sAMAccountName":        {"Contractors"},
			"sAMAccountType":        {"268435456"},
			"uSNChanged":            {"13010"},
			"uSNCreated":            {"13010"},
			"whenChanged":           {"20240327043009.0Z"},
			"whenCreated":           {"20240122063740.0Z"},
			"dSCorePropagationData": {"20240122063740.0Z"},
		},
	}

	// Users.
	userAdmin = entry{
		dn: "CN=Administrator,CN=Users,DC=testserver,DC=local",
		attrs: map[string][]string{
			"adminCount":             {"1"},
			"badPasswordTime":        {"133517595269561536"},
			"badPwdCount":            {"0"},
			"cn":                     {"Administrator"},
			"codePage":               {"0"},
			"countryCode":            {"0"},
			"description":            {"Built-in account for administering the computer/domain"},
			"distinguishedName":      {"CN=Administrator,CN=Users,DC=testserver,DC=local"},
			"instanceType":           {"4"},
			"isCriticalSystemObject": {"TRUE"},
			"lastLogoff":             {"0"},
			"lastLogon":              {"133518894621812823"},
			"lastLogonTimestamp":     {"133560378096399883"},
			"logonCount":             {"8"},
			"mail":                   {"admin@testserver.local"},
			"memberOf":               {"CN=Domain Admins,CN=Users,DC=testserver,DC=local", "CN=Domain Users,CN=Users,DC=testserver,DC=local"},
			"name":                   {"Administrator"},
			"objectCategory":         {"CN=Person,CN=Schema,CN=Configuration,DC=testserver,DC=local"},
			"objectClass":            {"top", "person", "organizationalPerson", "user"},
			"objectGUID":             {string(makeGUID(0x20))},
			"objectSid":              {string(makeSID(500))},
			"primaryGroupID":         {"513"},
			"pwdLastSet":             {"133503717398703568"},
			"sAMAccountName":         {"Administrator"},
			"sAMAccountType":         {"805306368"},
			"uSNChanged":             {"25166"},
			"uSNCreated":             {"8196"},
			"userAccountControl":     {"66048"},
			"userPrincipalName":      {"Administrator@testserver.local"},
			"whenChanged":            {"20240327043009.0Z"},
			"whenCreated":            {"20240122063659.0Z"},
			"dSCorePropagationData":  {"20240122063740.0Z"},
			"showInAdvancedViewOnly": {"FALSE"},
			"accountExpires":         {"9223372036854775807"},
		},
	}

	// Devices.
	deviceWorkstation01 = entry{
		dn: "CN=WORKSTATION-01,CN=Computers,DC=testserver,DC=local",
		attrs: map[string][]string{
			"badPasswordTime":        {"133251039041149826"},
			"badPwdCount":            {"0"},
			"cn":                     {"WORKSTATION-01"},
			"codePage":               {"0"},
			"countryCode":            {"0"},
			"dNSHostName":            {"WORKSTATION-01.testserver.local"},
			"description":            {"Test workstation"},
			"distinguishedName":      {"CN=WORKSTATION-01,CN=Computers,DC=testserver,DC=local"},
			"instanceType":           {"4"},
			"lastLogon":              {"133560378187867226"},
			"lastLogonTimestamp":     {"133559521557840088"},
			"logonCount":             {"100"},
			"memberOf":               {"CN=Domain Computers,CN=Users,DC=testserver,DC=local"},
			"name":                   {"WORKSTATION-01"},
			"objectCategory":         {"CN=Computer,CN=Schema,CN=Configuration,DC=testserver,DC=local"},
			"objectClass":            {"top", "person", "organizationalPerson", "user", "computer"},
			"objectGUID":             {string(makeGUID(0x30))},
			"objectSid":              {string(makeSID(1001))},
			"operatingSystem":        {"Windows 11 Enterprise"},
			"operatingSystemVersion": {"10.0 (22631)"},
			"primaryGroupID":         {"515"},
			"pwdLastSet":             {"133559521369983472"},
			"sAMAccountName":         {"WORKSTATION-01$"},
			"sAMAccountType":         {"805306369"},
			"servicePrincipalName":   {"HOST/WORKSTATION-01", "HOST/WORKSTATION-01.testserver.local"},
			"uSNChanged":             {"30000"},
			"uSNCreated":             {"29000"},
			"userAccountControl":     {"4096"},
			"whenChanged":            {"20240327043009.0Z"},
			"whenCreated":            {"20240122063740.0Z"},
			"dSCorePropagationData":  {"20240122063740.0Z"},
			"accountExpires":         {"9223372036854775807"},
		},
	}

	allGroups  = []entry{groupDomainUsers, groupDomainAdmins, groupDomainComputers, groupDecommissioned, groupContractors}
	allUsers   = []entry{userAdmin}
	allDevices = []entry{deviceWorkstation01}
)

// makeGUID builds a 16-byte Microsoft GUID with a distinguishing seed byte.
func makeGUID(seed byte) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], uint32(seed)<<16|0x0001)
	binary.LittleEndian.PutUint16(b[4:6], 0x0002)
	binary.LittleEndian.PutUint16(b[6:8], 0x0003)
	b[8] = 0x04
	b[9] = 0x05
	b[10] = 0x06
	b[11] = 0x07
	b[12] = 0x08
	b[13] = 0x09
	b[14] = seed
	b[15] = 0x0B
	return b
}

// makeSID builds a binary SID for the domain S-1-5-21-374105552-1189110957-4047727897-{rid}.
func makeSID(rid uint32) []byte {
	b := make([]byte, 28)
	b[0] = 1 // revision
	b[1] = 5 // sub-authority count
	// Identifier authority: 5 (NT Authority)
	b[7] = 5
	// Sub-authority 1: 21
	binary.LittleEndian.PutUint32(b[8:12], 21)
	// Sub-authority 2: 374105552
	binary.LittleEndian.PutUint32(b[12:16], 374105552)
	// Sub-authority 3: 1189110957
	binary.LittleEndian.PutUint32(b[16:20], 1189110957)
	// Sub-authority 4: 4047727897
	binary.LittleEndian.PutUint32(b[20:24], 4047727897)
	// Sub-authority 5: RID
	binary.LittleEndian.PutUint32(b[24:28], rid)
	return b
}

func main() {
	s, err := gldap.NewServer()
	if err != nil {
		log.Fatalf("unable to create ldap server: %s", err)
	}

	r, err := gldap.NewMux()
	if err != nil {
		log.Fatalf("unable to create mux: %s", err)
	}
	r.Bind(bindHandler)
	r.Search(searchHandler)
	s.Router(r)

	go func() {
		log.Printf("LDAP server listening on :%d", ldapPort)
		if err := s.Run(fmt.Sprintf(":%d", ldapPort)); err != nil {
			log.Fatalf("ldap server error: %s", err)
		}
	}()

	// HTTP health endpoint for Docker healthcheck.
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "OK")
	})
	log.Printf("HTTP health endpoint on :%d", httpPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil))
}

func bindHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(
		gldap.WithResponseCode(gldap.ResultInvalidCredentials),
	)
	defer func() { w.Write(resp) }()

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		log.Printf("not a simple bind message: %s", err)
		return
	}

	switch {
	case m.UserName == bindUser && m.Password == bindPass:
		resp.SetResultCode(gldap.ResultSuccess)
		log.Printf("bind success for %s", m.UserName)
		return
	case m.UserName == bindUserSpecial && m.Password == bindPassSpecial:
		resp.SetResultCode(gldap.ResultSuccess)
		log.Printf("bind success for %s", m.UserName)
		return
	}
	log.Printf("bind failed for %s (password length %d)", m.UserName, len(m.Password))
}

func searchHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewSearchDoneResponse()
	defer func() { w.Write(resp) }()

	m, err := r.GetSearchMessage()
	if err != nil {
		log.Printf("not a search message: %s", err)
		return
	}

	log.Printf("search base=%q scope=%d filter=%q", m.BaseDN, m.Scope, m.Filter)

	filter := m.Filter

	switch {
	case isEmptyGroupFilter(filter):
		writeEntries(w, r, emptyGroups())
	case isGroupFilter(filter):
		writeEntries(w, r, allGroups)
	case isUserFilter(filter):
		writeEntries(w, r, allUsers)
	case isDeviceFilter(filter):
		writeEntries(w, r, allDevices)
	default:
		log.Printf("unmatched filter: %s", filter)
	}

	resp.SetResultCode(gldap.ResultSuccess)
}

func writeEntries(w *gldap.ResponseWriter, r *gldap.Request, entries []entry) {
	for _, e := range entries {
		entry := r.NewSearchResponseEntry(e.dn, gldap.WithAttributes(e.attrs))
		w.Write(entry)
	}
}

func emptyGroups() []entry {
	var result []entry
	for _, g := range allGroups {
		if _, hasMember := g.attrs["member"]; !hasMember {
			result = append(result, g)
		}
	}
	return result
}

// isEmptyGroupFilter matches filters like (&(objectClass=group)(!(member=*)))
// with optional whenChanged conjunction.
func isEmptyGroupFilter(f string) bool {
	return strings.Contains(f, "objectClass=group") && strings.Contains(f, "!(member=*)")
}

// isGroupFilter matches (objectClass=group) with optional whenChanged.
func isGroupFilter(f string) bool {
	return strings.Contains(f, "objectClass=group") && !strings.Contains(f, "!(member=*)")
}

// isUserFilter matches (&(objectCategory=person)(objectClass=user)) with
// optional whenChanged or memberOf conjunctions.
func isUserFilter(f string) bool {
	return strings.Contains(f, "objectCategory=person") && strings.Contains(f, "objectClass=user")
}

// isDeviceFilter matches (&(objectClass=computer)(objectClass=user)) with
// optional whenChanged or memberOf conjunctions.
func isDeviceFilter(f string) bool {
	return strings.Contains(f, "objectClass=computer") && strings.Contains(f, "objectClass=user")
}

func init() {
	// Ensure time parsing works for the dense time layout used by AD.
	const layout = "20060102150405.0Z"
	if _, err := time.Parse(layout, "20240122063740.0Z"); err != nil {
		log.Fatalf("time parse sanity check failed: %s", err)
	}
}
