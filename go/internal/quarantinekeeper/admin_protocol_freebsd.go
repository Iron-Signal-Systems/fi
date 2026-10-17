// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"errors"
	"io"
)

const AdminProtocolVersion = 1

// AdminReleaseRequest carries requested action, never asserted caller identity.
// The keeper obtains operator identity exclusively from FreeBSD peer credentials.
type AdminReleaseRequest struct {
	Version       int    `json:"version"`
	Operation     string `json:"operation"`
	SourceID      string `json:"source_id"`
	ConfirmSource string `json:"confirm_source"`
	Reference     string `json:"reference"`
	Justification string `json:"justification"`
}

// AdminReleaseResponse does not contain a release token or delegated authority.
type AdminReleaseResponse struct {
	Version   int    `json:"version"`
	Status    string `json:"status"`
	AuditPath string `json:"audit_path,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

func (request AdminReleaseRequest) Validate() error {
	if request.Version != AdminProtocolVersion || request.Operation != "release" {
		return errors.New("unsupported administrative release operation")
	}
	return validateKeeperReleaseRequest(KeeperReleaseRequest{
		SourceID:      request.SourceID,
		ConfirmSource: request.ConfirmSource,
		Reference:     request.Reference,
		Justification: request.Justification,
		OperatorUID:   0,
	})
}

func (response AdminReleaseResponse) Validate() error {
	if response.Version != AdminProtocolVersion {
		return errors.New("invalid administrative response version")
	}
	switch response.Status {
	case "released":
		if response.AuditPath == "" || response.ErrorCode != "" {
			return errors.New("released response requires audit path and no error code")
		}
	case "error":
		if response.AuditPath != "" || !validUpperCode(response.ErrorCode, 64) {
			return errors.New("failed release requires an error code and no audit path")
		}
	default:
		return errors.New("invalid administrative response status")
	}
	return nil
}

func ReadAdminReleaseRequest(reader io.Reader) (AdminReleaseRequest, error) {
	var request AdminReleaseRequest
	if err := readFrame(reader, &request,
		"version", "operation", "source_id", "confirm_source", "reference", "justification",
	); err != nil {
		return AdminReleaseRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return AdminReleaseRequest{}, err
	}
	return request, nil
}

func WriteAdminReleaseRequest(writer io.Writer, request AdminReleaseRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	return writeFrame(writer, request)
}

func ReadAdminReleaseResponse(reader io.Reader) (AdminReleaseResponse, error) {
	var response AdminReleaseResponse
	if err := readFrame(reader, &response, "version", "status", "audit_path", "error_code"); err != nil {
		return AdminReleaseResponse{}, err
	}
	if err := response.Validate(); err != nil {
		return AdminReleaseResponse{}, err
	}
	return response, nil
}

func WriteAdminReleaseResponse(writer io.Writer, response AdminReleaseResponse) error {
	if err := response.Validate(); err != nil {
		return err
	}
	return writeFrame(writer, response)
}
