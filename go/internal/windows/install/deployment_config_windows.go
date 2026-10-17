// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

const (
	deploymentConfigApprovalVersion = "FI-DEPLOYMENT-CONFIG-V1"
	deploymentConfigSourceFile      = "FILE"
	deploymentConfigSourceManual    = "MANUAL"
)

type DeploymentConfigApproval struct {
	DigestSHA256 string
	Given        bool
}

type DeploymentConfigProposal struct {
	DigestSHA256     string
	Inputs           PlanInputs
	InstallPath      string
	Normalized       []byte
	NormalizedSHA256 string
	SourceMode       string
	SourcePath       string
	SourceSHA256     string
}

func BuildManualDeploymentConfigProposal(
	report Report,
	inputs PlanInputs,
) (DeploymentConfigProposal, error) {
	if inputs.ConfigEmpty() {
		return DeploymentConfigProposal{}, errors.New(
			"manual FI deployment configuration is empty",
		)
	}

	return buildDeploymentConfigProposal(
		report,
		inputs,
		deploymentConfigSourceManual,
		"",
		"",
	)
}

func LoadDeploymentConfigProposal(
	report Report,
	path string,
) (DeploymentConfigProposal, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return DeploymentConfigProposal{}, errors.New(
			"FI deployment configuration path is required",
		)
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"resolve FI deployment configuration path %q: %w",
			path,
			err,
		)
	}
	absolutePath = filepath.Clean(absolutePath)

	info, err := os.Lstat(absolutePath)
	if err != nil {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"inspect FI deployment configuration %s: %w",
			absolutePath,
			err,
		)
	}
	if !info.Mode().IsRegular() {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"FI deployment configuration %s is not a regular file",
			absolutePath,
		)
	}

	raw, err := os.ReadFile(absolutePath)
	if err != nil {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"read FI deployment configuration %s: %w",
			absolutePath,
			err,
		)
	}

	parsed, err := config.Parse(bytes.NewReader(raw))
	if err != nil {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"validate FI deployment configuration %s: %w",
			absolutePath,
			err,
		)
	}
	if parsed.VersionID != config.Version11 {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"FI deployment configuration %s must use version_id %s; observed=%s",
			absolutePath,
			config.Version11,
			parsed.VersionID,
		)
	}

	inputs := PlanInputs{
		GovernedRoots: append(
			[]string(nil),
			parsed.GovernedRoots...,
		),
		ReceiverAddress: strings.TrimSpace(parsed.Receiver.Address),
		ReceiverName:    strings.TrimSpace(parsed.Receiver.Name),
		SpoolDir:        strings.TrimSpace(parsed.Storage.SpoolDir),
		StageDir:        strings.TrimSpace(parsed.Storage.StageDir),
		StateDir:        strings.TrimSpace(parsed.Storage.StateDir),
	}

	digest := sha256.Sum256(raw)
	proposal, err := buildDeploymentConfigProposal(
		report,
		inputs,
		deploymentConfigSourceFile,
		absolutePath,
		hex.EncodeToString(digest[:]),
	)
	if err != nil {
		return DeploymentConfigProposal{}, err
	}

	canonical, err := approval2OperationalConfigValue(
		ConfigState{
			GovernedRoots:   append([]string(nil), inputs.GovernedRoots...),
			Path:            proposal.InstallPath,
			Presence:        presenceAbsent,
			ReceiverAddress: inputs.ReceiverAddress,
			ReceiverName:    inputs.ReceiverName,
			SourceID:        deploymentConfigExpectedSourceID(report),
			SpoolDir:        inputs.SpoolDir,
			StageDir:        inputs.StageDir,
			StateDir:        inputs.StateDir,
		},
	)
	if err != nil {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"build canonical FI deployment configuration contract: %w",
			err,
		)
	}

	if !sameApproval2OperationalConfig(parsed, canonical) {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"FI deployment configuration %s does not match the exact supported FI 1.1 operational contract; fixed collector/spool/sender/receiver-timeout/troubleshoot values and derived source.id must match the configuration FI will install",
			absolutePath,
		)
	}

	return proposal, nil
}

func PromptDeploymentConfigApproval(
	reader io.Reader,
	writer io.Writer,
	proposal DeploymentConfigProposal,
) (DeploymentConfigApproval, error) {
	if reader == nil || writer == nil {
		return DeploymentConfigApproval{}, errors.New(
			"FI deployment configuration approval requires input and output streams",
		)
	}
	if err := validateDeploymentConfigProposal(proposal); err != nil {
		return DeploymentConfigApproval{}, err
	}

	token := "APPROVE-CONFIG " + strings.ToUpper(proposal.DigestSHA256[:16])

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "FI WINDOWS INSTALLER - CONFIGURATION APPROVAL")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintf(writer, "Configuration mode:   %s\n", proposal.SourceMode)
	if proposal.SourceMode == deploymentConfigSourceFile {
		fmt.Fprintf(writer, "Source file:          %s\n", proposal.SourcePath)
		fmt.Fprintf(writer, "Source file SHA256:   %s\n", strings.ToUpper(proposal.SourceSHA256))
	} else {
		fmt.Fprintln(writer, "Source file:          not_applicable (constructed from manual installer input)")
	}
	fmt.Fprintf(writer, "Install destination:  %s\n", proposal.InstallPath)
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "--- BEGIN EXACT NORMALIZED FI CONFIGURATION TO INSTALL ---")
	fmt.Fprint(writer, string(proposal.Normalized))
	if len(proposal.Normalized) == 0 || proposal.Normalized[len(proposal.Normalized)-1] != '\n' {
		fmt.Fprintln(writer)
	}
	fmt.Fprintln(writer, "--- END EXACT NORMALIZED FI CONFIGURATION TO INSTALL ---")
	fmt.Fprintln(writer, "")
	fmt.Fprintf(writer, "Normalized configuration SHA256: %s\n", strings.ToUpper(proposal.NormalizedSHA256))
	fmt.Fprintf(writer, "Configuration approval SHA256:   %s\n", strings.ToUpper(proposal.DigestSHA256))
	fmt.Fprintln(writer, "The approval digest binds the source mode, source path/hash when present,")
	fmt.Fprintln(writer, "fixed install destination, normalized configuration hash, and exact normalized bytes.")
	writeFailClosedApprovalPrompt(
		writer,
		token,
		"configuration approval",
	)

	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return DeploymentConfigApproval{}, fmt.Errorf(
			"read FI deployment configuration approval: %w",
			err,
		)
	}
	if strings.TrimSpace(line) != token {
		return DeploymentConfigApproval{}, errors.New(
			"FI deployment configuration approval was not granted; no configuration or installer mutation was performed",
		)
	}

	return DeploymentConfigApproval{
		DigestSHA256: proposal.DigestSHA256,
		Given:        true,
	}, nil
}

func WriteDeploymentConfigProposal(
	writer io.Writer,
	proposal DeploymentConfigProposal,
) error {
	if writer == nil {
		return errors.New("FI deployment configuration output writer is required")
	}
	if err := validateDeploymentConfigProposal(proposal); err != nil {
		return err
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "FI WINDOWS INSTALLER - DEPLOYMENT CONFIGURATION")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintf(writer, "Configuration mode:   %s\n", proposal.SourceMode)
	if proposal.SourceMode == deploymentConfigSourceFile {
		fmt.Fprintf(writer, "Source file:          %s\n", proposal.SourcePath)
		fmt.Fprintf(writer, "Source file SHA256:   %s\n", strings.ToUpper(proposal.SourceSHA256))
	}
	fmt.Fprintf(writer, "Install destination:  %s\n", proposal.InstallPath)
	fmt.Fprintf(writer, "Normalized SHA256:    %s\n", strings.ToUpper(proposal.NormalizedSHA256))
	fmt.Fprintln(writer, "")
	fmt.Fprint(writer, string(proposal.Normalized))
	return nil
}

func buildDeploymentConfigProposal(
	report Report,
	inputs PlanInputs,
	sourceMode string,
	sourcePath string,
	sourceSHA256 string,
) (DeploymentConfigProposal, error) {
	if report.Config.Presence != presenceAbsent {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"deployment configuration input is supported only for a new install with FI operational configuration presence=%s; observed=%s",
			presenceAbsent,
			report.Config.Presence,
		)
	}

	working := report
	var plan InstallPlan
	planConfiguration(&plan, &working, inputs)
	if plan.HasBlockers() {
		return DeploymentConfigProposal{}, errors.New(
			"FI deployment configuration proposal contains blockers",
		)
	}
	if plan.HasQuestions() {
		return DeploymentConfigProposal{}, fmt.Errorf(
			"FI deployment configuration proposal is incomplete: %s",
			strings.Join(plan.Questions, "; "),
		)
	}

	value, err := approval2OperationalConfigValue(working.Config)
	if err != nil {
		return DeploymentConfigProposal{}, err
	}
	normalized, err := renderApproval2OperationalConfig(value)
	if err != nil {
		return DeploymentConfigProposal{}, err
	}

	normalizedDigest := sha256.Sum256(normalized)
	proposal := DeploymentConfigProposal{
		Inputs:           inputs,
		InstallPath:      filepath.Clean(strings.TrimSpace(working.Config.Path)),
		Normalized:       append([]byte(nil), normalized...),
		NormalizedSHA256: hex.EncodeToString(normalizedDigest[:]),
		SourceMode:       strings.TrimSpace(sourceMode),
		SourcePath:       filepath.Clean(strings.TrimSpace(sourcePath)),
		SourceSHA256:     strings.ToLower(strings.TrimSpace(sourceSHA256)),
	}
	if proposal.SourceMode == deploymentConfigSourceManual {
		proposal.SourcePath = ""
		proposal.SourceSHA256 = ""
	}

	digest, err := deploymentConfigApprovalDigest(proposal)
	if err != nil {
		return DeploymentConfigProposal{}, err
	}
	proposal.DigestSHA256 = digest

	if err := validateDeploymentConfigProposal(proposal); err != nil {
		return DeploymentConfigProposal{}, err
	}
	return proposal, nil
}

func deploymentConfigApprovalDigest(
	proposal DeploymentConfigProposal,
) (string, error) {
	if proposal.SourceMode != deploymentConfigSourceFile &&
		proposal.SourceMode != deploymentConfigSourceManual {
		return "", fmt.Errorf(
			"unsupported FI deployment configuration source mode %q",
			proposal.SourceMode,
		)
	}
	if len(proposal.Normalized) == 0 {
		return "", errors.New("normalized FI deployment configuration is empty")
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "%s\n", deploymentConfigApprovalVersion)
	fmt.Fprintf(&builder, "SOURCE_MODE=%s\n", proposal.SourceMode)
	fmt.Fprintf(&builder, "SOURCE_PATH=%s\n", proposal.SourcePath)
	fmt.Fprintf(&builder, "SOURCE_SHA256=%s\n", strings.ToLower(proposal.SourceSHA256))
	fmt.Fprintf(&builder, "INSTALL_PATH=%s\n", proposal.InstallPath)
	fmt.Fprintf(&builder, "NORMALIZED_SHA256=%s\n", strings.ToLower(proposal.NormalizedSHA256))
	fmt.Fprintf(&builder, "NORMALIZED_LENGTH=%d\n", len(proposal.Normalized))

	hash := sha256.New()
	if _, err := io.WriteString(hash, builder.String()); err != nil {
		return "", err
	}
	if _, err := hash.Write(proposal.Normalized); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func deploymentConfigExpectedSourceID(
	report Report,
) string {
	computer := strings.TrimSpace(report.Host.Computer)
	domain := strings.TrimSpace(report.Host.DomainDNS)
	if computer == "" || domain == "" ||
		strings.EqualFold(computer, notKnown) ||
		strings.EqualFold(domain, notKnown) {
		return ""
	}
	return strings.ToLower(computer + "." + domain)
}

func validateDeploymentConfigProposal(
	proposal DeploymentConfigProposal,
) error {
	if proposal.SourceMode != deploymentConfigSourceFile &&
		proposal.SourceMode != deploymentConfigSourceManual {
		return fmt.Errorf(
			"unsupported FI deployment configuration source mode %q",
			proposal.SourceMode,
		)
	}
	if strings.TrimSpace(proposal.InstallPath) == "" {
		return errors.New("FI deployment configuration install destination is empty")
	}
	if len(proposal.Normalized) == 0 {
		return errors.New("normalized FI deployment configuration is empty")
	}
	if !validSHA256Hex(proposal.NormalizedSHA256) {
		return errors.New("normalized FI deployment configuration SHA-256 is invalid")
	}
	if proposal.SourceMode == deploymentConfigSourceFile {
		if strings.TrimSpace(proposal.SourcePath) == "" {
			return errors.New("FI deployment configuration source file path is empty")
		}
		if !validSHA256Hex(proposal.SourceSHA256) {
			return errors.New("FI deployment configuration source file SHA-256 is invalid")
		}
	} else if proposal.SourcePath != "" || proposal.SourceSHA256 != "" {
		return errors.New("manual FI deployment configuration must not carry source-file identity")
	}
	if !validSHA256Hex(proposal.DigestSHA256) {
		return errors.New("FI deployment configuration approval SHA-256 is invalid")
	}

	digest := sha256.Sum256(proposal.Normalized)
	if !strings.EqualFold(
		hex.EncodeToString(digest[:]),
		proposal.NormalizedSHA256,
	) {
		return errors.New("normalized FI deployment configuration bytes do not match their SHA-256")
	}

	expectedDigest, err := deploymentConfigApprovalDigest(
		DeploymentConfigProposal{
			Inputs:           proposal.Inputs,
			InstallPath:      proposal.InstallPath,
			Normalized:       proposal.Normalized,
			NormalizedSHA256: proposal.NormalizedSHA256,
			SourceMode:       proposal.SourceMode,
			SourcePath:       proposal.SourcePath,
			SourceSHA256:     proposal.SourceSHA256,
		},
	)
	if err != nil {
		return err
	}
	if !strings.EqualFold(expectedDigest, proposal.DigestSHA256) {
		return errors.New("FI deployment configuration approval digest does not match the proposal")
	}

	return nil
}
