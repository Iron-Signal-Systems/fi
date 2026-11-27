// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
)

const fiReceiverTLSTemplateName = "FI-Receiver-TLS"

type CATemplateDefinitionSnapshot struct {
	Name string
	OID  string
}

type CATemplatePublicationApproval struct {
	DigestSHA256 string
	Given        bool
}

type CATemplatePublicationPlan struct {
	CAConfiguration     string
	CurrentTemplates    []string
	DigestSHA256        string
	DomainController    string
	MissingTemplates    []string
	ResultingTemplates  []string
	TemplateDefinitions []CATemplateDefinitionSnapshot
}

func BuildCATemplatePublicationPlan(
	report Report,
) (CATemplatePublicationPlan, bool, error) {
	if strings.TrimSpace(report.AD.DomainController) == "" ||
		strings.TrimSpace(report.AD.ConfigurationNamingContext) == "" {
		return CATemplatePublicationPlan{}, false, errors.New(
			"Active Directory domain controller/configuration naming context is unavailable",
		)
	}

	session, err := openLDAPSession(
		report.AD.DomainController,
	)
	if err != nil {
		return CATemplatePublicationPlan{}, false, fmt.Errorf(
			"open LDAP session for CA template-publication planning: %w",
			err,
		)
	}
	defer session.close()

	requiredTemplates := []string{
		fiTransportClientTemplateName,
		fiBatchSigningTemplateName,
		fiReceiverTLSTemplateName,
	}

	definitions := make(
		[]CATemplateDefinitionSnapshot,
		0,
		len(requiredTemplates),
	)

	// Publication is allowed only for existing AD template definitions. Creating
	// a certificate-template definition is a separate shared-PKI mutation with a
	// separate approval contract.
	for _, templateName := range requiredTemplates {
		oid, err := resolveCertificateTemplateOID(
			session,
			report.AD.ConfigurationNamingContext,
			templateName,
		)
		if err != nil {
			return CATemplatePublicationPlan{}, false, fmt.Errorf(
				"certificate template definition %s is unavailable; FI will not create a new AD template definition under the CA-publication approval: %w",
				templateName,
				err,
			)
		}
		definitions = append(
			definitions,
			CATemplateDefinitionSnapshot{
				Name: templateName,
				OID:  strings.TrimSpace(oid),
			},
		)
	}

	cas, err := discoverEnterpriseCertificateAuthorities(
		session,
		report.AD.ConfigurationNamingContext,
	)
	if err != nil {
		return CATemplatePublicationPlan{}, false, err
	}

	return buildCATemplatePublicationPlanFromCAs(
		report.AD.DomainController,
		cas,
		requiredTemplates,
		definitions,
	)
}

func PromptCATemplatePublicationApproval(
	reader io.Reader,
	writer io.Writer,
	plan CATemplatePublicationPlan,
) (CATemplatePublicationApproval, error) {
	if reader == nil || writer == nil {
		return CATemplatePublicationApproval{}, errors.New(
			"CA template-publication approval requires input and output streams",
		)
	}
	if err := validateCATemplatePublicationPlan(plan); err != nil {
		return CATemplatePublicationApproval{}, err
	}

	token := "APPROVE-CA-TEMPLATES " + plan.DigestSHA256[:16]
	argument := "+" + strings.Join(plan.MissingTemplates, ",")

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "FI WINDOWS INSTALLER - SHARED CA TEMPLATE PUBLICATION APPROVAL")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "This is a shared Enterprise CA configuration change.")
	fmt.Fprintf(writer, "Issuing CA:           %s\n", plan.CAConfiguration)
	fmt.Fprintf(writer, "Authoritative DC:     %s\n", plan.DomainController)
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "EXISTING AD TEMPLATE DEFINITIONS TO BE PUBLISHED:")
	for _, definition := range sortedCATemplateDefinitions(plan.TemplateDefinitions) {
		if !containsCATemplateName(plan.MissingTemplates, definition.Name) {
			continue
		}
		fmt.Fprintf(
			writer,
			"  %s  OID=%s\n",
			definition.Name,
			definition.OID,
		)
	}
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "CURRENT CA certificateTemplates VALUES:")
	for _, templateName := range plan.CurrentTemplates {
		fmt.Fprintf(writer, "  %s\n", templateName)
	}
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "RESULTING CA certificateTemplates VALUES AFTER THIS CHANGE:")
	for _, templateName := range plan.ResultingTemplates {
		fmt.Fprintf(writer, "  %s\n", templateName)
	}
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "EXACT PROCESS + ARGUMENTS FI WILL EXECUTE:")
	fmt.Fprintln(writer, "  executable: certutil.exe")
	fmt.Fprintf(writer, "  argv[1]:    -config\n")
	fmt.Fprintf(writer, "  argv[2]:    %s\n", plan.CAConfiguration)
	fmt.Fprintf(writer, "  argv[3]:    -dc\n")
	fmt.Fprintf(writer, "  argv[4]:    %s\n", plan.DomainController)
	fmt.Fprintf(writer, "  argv[5]:    -SetCATemplates\n")
	fmt.Fprintf(writer, "  argv[6]:    %s\n", argument)
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "POWERSHELL EQUIVALENT FOR OPERATOR REVIEW:")
	fmt.Fprintf(
		writer,
		"  & certutil.exe -config %q -dc %q -SetCATemplates %q\n",
		plan.CAConfiguration,
		plan.DomainController,
		argument,
	)
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "The CA receives only the listed certificate-template CN values.")
	fmt.Fprintln(writer, "Template cryptographic settings, EKUs, key usage, subject/SAN rules,")
	fmt.Fprintln(writer, "template ACLs, and CA keys remain unchanged in this approval.")
	fmt.Fprintln(writer, "No certificate is issued by this operation.")
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "The approval digest binds the exact CA, DC, template name/OID identities,")
	fmt.Fprintln(writer, "current publication values, resulting publication values, and certutil argv.")
	fmt.Fprintf(writer, "Publication approval SHA256: %s\n", plan.DigestSHA256)
	writeFailClosedApprovalPrompt(
		writer,
		token,
		"CA template-publication approval",
	)

	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return CATemplatePublicationApproval{}, fmt.Errorf(
			"read CA template-publication approval: %w",
			err,
		)
	}
	if strings.TrimSpace(line) != token {
		return CATemplatePublicationApproval{}, errors.New(
			"CA template-publication approval was not granted; no CA configuration change was performed",
		)
	}

	return CATemplatePublicationApproval{
		DigestSHA256: plan.DigestSHA256,
		Given:        true,
	}, nil
}

func ApplyCATemplatePublication(
	writer io.Writer,
	report Report,
	approvedPlan CATemplatePublicationPlan,
	approval CATemplatePublicationApproval,
) error {
	if writer == nil {
		return errors.New("CA template-publication output writer is required")
	}
	if err := validateCATemplatePublicationPlan(approvedPlan); err != nil {
		return err
	}
	if !approval.Given || !strings.EqualFold(
		strings.TrimSpace(approval.DigestSHA256),
		approvedPlan.DigestSHA256,
	) {
		return errors.New("CA template-publication approval digest is absent or does not match the approved plan")
	}

	// Mandatory pre-mutation rediscovery. Shared CA configuration may not be
	// changed from a stale approval digest.
	currentPlan, required, err := BuildCATemplatePublicationPlan(report)
	if err != nil {
		return fmt.Errorf("pre-publication rediscovery failed: %w", err)
	}
	if !required {
		return errors.New("CA template publication is no longer required; approved publication plan is stale and no mutation was performed")
	}
	if !strings.EqualFold(currentPlan.DigestSHA256, approvedPlan.DigestSHA256) {
		return fmt.Errorf(
			"CA template publication state changed after approval: approved=%s current=%s; no mutation was performed",
			approvedPlan.DigestSHA256,
			currentPlan.DigestSHA256,
		)
	}

	if _, err := exec.LookPath("certutil.exe"); err != nil {
		return fmt.Errorf("locate certutil.exe for CA template publication: %w", err)
	}

	argument := "+" + strings.Join(currentPlan.MissingTemplates, ",")
	command := exec.Command(
		"certutil.exe",
		"-config",
		currentPlan.CAConfiguration,
		"-dc",
		currentPlan.DomainController,
		"-SetCATemplates",
		argument,
	)

	fmt.Fprintln(writer, "APPLY CA TEMPLATE PUBLICATION - EXACT EXECUTION")
	fmt.Fprintln(writer, "  executable: certutil.exe")
	fmt.Fprintf(writer, "  -config:    %s\n", currentPlan.CAConfiguration)
	fmt.Fprintf(writer, "  -dc:        %s\n", currentPlan.DomainController)
	fmt.Fprintln(writer, "  verb:       -SetCATemplates")
	fmt.Fprintf(writer, "  value:      %s\n", argument)

	output, commandErr := command.CombinedOutput()
	trimmedOutput := strings.TrimSpace(string(output))
	if trimmedOutput != "" {
		fmt.Fprintf(writer, "certutil: %s\n", trimmedOutput)
	}
	if commandErr != nil {
		return fmt.Errorf(
			"certutil -SetCATemplates failed after explicit approval: %w; output=%q; FI will not guess rollback ownership for shared CA configuration",
			commandErr,
			trimmedOutput,
		)
	}

	postReport := Discover()
	if err := verifyCATemplatePublicationResult(
		postReport,
		currentPlan,
	); err != nil {
		return err
	}

	fmt.Fprintln(writer, "CA TEMPLATE PUBLICATION RESULT: PASS")
	fmt.Fprintln(writer, "The exact approved certificateTemplates result is present on the selected Enterprise CA.")
	fmt.Fprintln(writer, "The approved publication is durable shared CA configuration and is not rolled back by a later host-install failure.")
	return nil
}

func buildCATemplatePublicationPlanFromCAs(
	domainController string,
	cas []enterpriseCertificateAuthorityState,
	requiredTemplates []string,
	definitions []CATemplateDefinitionSnapshot,
) (CATemplatePublicationPlan, bool, error) {
	if len(requiredTemplates) == 0 {
		return CATemplatePublicationPlan{}, false, errors.New("required certificate-template list is empty")
	}
	if len(cas) == 0 {
		return CATemplatePublicationPlan{}, false, errors.New("no Enterprise CA was discovered")
	}

	var target *enterpriseCertificateAuthorityState
	complete := enterpriseCAsPublishingAll(cas, requiredTemplates)
	if len(complete) != 0 {
		if len(complete) == 1 {
			target = &complete[0]
		} else {
			return CATemplatePublicationPlan{}, false, nil
		}
	} else if len(cas) == 1 {
		target = &cas[0]
	} else {
		candidates := make([]int, 0, len(cas))
		for index := range cas {
			for _, templateName := range requiredTemplates {
				if enterpriseCAPublishesTemplate(cas[index], templateName) {
					candidates = append(candidates, index)
					break
				}
			}
		}
		if len(candidates) != 1 {
			return CATemplatePublicationPlan{}, false, fmt.Errorf(
				"no single unambiguous Enterprise CA can be selected for FI template publication; discovered_cas=%s; FI refuses to choose a shared CA automatically",
				strings.Join(enterpriseCAConfigurations(cas), ", "),
			)
		}
		target = &cas[candidates[0]]
	}

	if target == nil {
		return CATemplatePublicationPlan{}, false, nil
	}

	current := sortedUniqueCATemplateValues(target.Templates)
	missing := make([]string, 0, len(requiredTemplates))
	for _, templateName := range requiredTemplates {
		if !enterpriseCAPublishesTemplate(*target, templateName) {
			missing = append(missing, templateName)
		}
	}
	missing = sortedUniqueCATemplateValues(missing)
	resulting := sortedUniqueCATemplateValues(
		append(append([]string(nil), current...), missing...),
	)

	plan := CATemplatePublicationPlan{
		CAConfiguration:    strings.TrimSpace(target.Configuration),
		CurrentTemplates:   current,
		DomainController:   strings.TrimSpace(domainController),
		MissingTemplates:   missing,
		ResultingTemplates: resulting,
		TemplateDefinitions: append(
			[]CATemplateDefinitionSnapshot(nil),
			definitions...,
		),
	}
	if plan.CAConfiguration == "" {
		return CATemplatePublicationPlan{}, false, errors.New("selected Enterprise CA configuration is empty")
	}
	if len(missing) == 0 {
		return plan, false, nil
	}

	plan.DigestSHA256 = caTemplatePublicationDigest(plan)
	return plan, true, nil
}

func caTemplatePublicationDigest(
	plan CATemplatePublicationPlan,
) string {
	definitions := sortedCATemplateDefinitions(plan.TemplateDefinitions)
	definitionLines := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		definitionLines = append(
			definitionLines,
			strings.TrimSpace(definition.Name)+"="+strings.TrimSpace(definition.OID),
		)
	}

	missing := sortedUniqueCATemplateValues(plan.MissingTemplates)
	current := sortedUniqueCATemplateValues(plan.CurrentTemplates)
	resulting := sortedUniqueCATemplateValues(plan.ResultingTemplates)
	argument := "+" + strings.Join(missing, ",")

	canonical := strings.Join(
		[]string{
			"FI-CA-TEMPLATE-PUBLICATION-V2",
			"CA=" + strings.TrimSpace(plan.CAConfiguration),
			"DC=" + strings.TrimSpace(plan.DomainController),
			"DEFINITIONS=" + strings.Join(definitionLines, ";"),
			"CURRENT=" + strings.Join(current, ","),
			"MISSING=" + strings.Join(missing, ","),
			"RESULTING=" + strings.Join(resulting, ","),
			"EXECUTABLE=certutil.exe",
			"ARGV=-config|" + strings.TrimSpace(plan.CAConfiguration) +
				"|-dc|" + strings.TrimSpace(plan.DomainController) +
				"|-SetCATemplates|" + argument,
		},
		"\n",
	)
	digest := sha256.Sum256([]byte(canonical))
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}

func containsCATemplateName(
	values []string,
	name string,
) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

func sortedCATemplateDefinitions(
	definitions []CATemplateDefinitionSnapshot,
) []CATemplateDefinitionSnapshot {
	result := append([]CATemplateDefinitionSnapshot(nil), definitions...)
	sort.Slice(
		result,
		func(i, j int) bool {
			return strings.ToLower(strings.TrimSpace(result[i].Name)) <
				strings.ToLower(strings.TrimSpace(result[j].Name))
		},
	)
	return result
}

func sortedUniqueCATemplateValues(
	values []string,
) []string {
	byLower := make(map[string]string)
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if _, exists := byLower[lower]; !exists {
			byLower[lower] = trimmed
		}
	}
	keys := make([]string, 0, len(byLower))
	for key := range byLower {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, byLower[key])
	}
	return result
}

func validateCATemplatePublicationPlan(
	plan CATemplatePublicationPlan,
) error {
	if strings.TrimSpace(plan.CAConfiguration) == "" {
		return errors.New("CA template-publication plan has no issuing CA")
	}
	if strings.TrimSpace(plan.DomainController) == "" {
		return errors.New("CA template-publication plan has no authoritative domain controller")
	}
	if len(plan.MissingTemplates) == 0 {
		return errors.New("CA template-publication plan contains no missing templates")
	}
	if len(plan.TemplateDefinitions) == 0 {
		return errors.New("CA template-publication plan contains no template-definition identities")
	}
	for _, missing := range plan.MissingTemplates {
		found := false
		for _, definition := range plan.TemplateDefinitions {
			if strings.EqualFold(strings.TrimSpace(definition.Name), strings.TrimSpace(missing)) &&
				strings.TrimSpace(definition.OID) != "" {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing template %s is not bound to an existing AD template name/OID identity", missing)
		}
	}
	expectedResult := sortedUniqueCATemplateValues(
		append(
			append([]string(nil), plan.CurrentTemplates...),
			plan.MissingTemplates...,
		),
	)
	if strings.Join(expectedResult, "\x00") != strings.Join(sortedUniqueCATemplateValues(plan.ResultingTemplates), "\x00") {
		return errors.New("CA template-publication resulting values are not the exact union of current values and missing templates")
	}
	expected := caTemplatePublicationDigest(plan)
	if !strings.EqualFold(strings.TrimSpace(plan.DigestSHA256), expected) {
		return fmt.Errorf(
			"CA template-publication plan digest mismatch: observed=%s expected=%s",
			plan.DigestSHA256,
			expected,
		)
	}
	return nil
}

func verifyCATemplatePublicationResult(
	report Report,
	approvedPlan CATemplatePublicationPlan,
) error {
	if strings.TrimSpace(report.AD.DomainController) == "" ||
		strings.TrimSpace(report.AD.ConfigurationNamingContext) == "" {
		return errors.New("post-publication Active Directory discovery is incomplete")
	}

	session, err := openLDAPSession(report.AD.DomainController)
	if err != nil {
		return fmt.Errorf("open LDAP session for post-publication verification: %w", err)
	}
	defer session.close()

	cas, err := discoverEnterpriseCertificateAuthorities(
		session,
		report.AD.ConfigurationNamingContext,
	)
	if err != nil {
		return fmt.Errorf("rediscover Enterprise CA after template publication: %w", err)
	}

	var matched *enterpriseCertificateAuthorityState
	for index := range cas {
		if strings.EqualFold(
			strings.TrimSpace(cas[index].Configuration),
			strings.TrimSpace(approvedPlan.CAConfiguration),
		) {
			matched = &cas[index]
			break
		}
	}
	if matched == nil {
		return fmt.Errorf(
			"approved Enterprise CA %s was not rediscovered after template publication",
			approvedPlan.CAConfiguration,
		)
	}

	observed := sortedUniqueCATemplateValues(matched.Templates)
	expected := sortedUniqueCATemplateValues(approvedPlan.ResultingTemplates)
	if strings.Join(observed, "\x00") != strings.Join(expected, "\x00") {
		return fmt.Errorf(
			"CA template publication returned success but exact resulting certificateTemplates values differ; ca=%s expected=%s observed=%s",
			approvedPlan.CAConfiguration,
			strings.Join(expected, ","),
			strings.Join(observed, ","),
		)
	}

	return nil
}
