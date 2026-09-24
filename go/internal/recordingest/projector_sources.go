// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"context"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

func projectCollectorIdentity(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.ProcessIdentityObservation) error {
	observedAt, err := parseRFC3339(value.ObservedAt, "collector_identity.observed_at")
	if err != nil {
		return err
	}
	tokenTypeRaw, err := parseUint(value.Token.TokenTypeRaw, 16, "collector_identity.token_type_raw")
	if err != nil {
		return err
	}
	elevationTypeRaw, err := parseUint(value.Token.ElevationTypeRaw, 16, "collector_identity.elevation_type_raw")
	if err != nil {
		return err
	}
	var userNameUse any
	if value.Token.User.NameUseRaw != "" {
		parsed, e := parseUint(value.Token.User.NameUseRaw, 32, "collector_identity.token_user_name_use_raw")
		if e != nil {
			return e
		}
		userNameUse = int64(parsed)
	}

	_, err = tx.Exec(ctx, `
INSERT INTO fi.collector_identity (
 source_record_id,observed_at,collection_method,computer_netbios_name,computer_dns_host_name,computer_dns_domain,computer_dns_fqdn,
 token_user_sid,token_user_account_name,token_user_domain_name,token_user_name_use_raw,token_user_name_use_name,
 token_type_raw,token_type_name,elevation_type_raw,elevation_type_name,elevated
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
`, sourceRecordID, observedAt, value.CollectionMethod, value.Computer.NetBIOSName, nullString(value.Computer.DNSHostName), nullString(value.Computer.DNSDomain), nullString(value.Computer.DNSFQDN),
		value.Token.User.SID, nullString(value.Token.User.AccountName), nullString(value.Token.User.DomainName), userNameUse, nullString(value.Token.User.NameUseName),
		int(tokenTypeRaw), value.Token.TokenTypeName, int(elevationTypeRaw), value.Token.ElevationTypeName, value.Token.Elevated)
	if err != nil {
		return fmt.Errorf("insert FI collector identity: %w", err)
	}

	for _, group := range value.Token.Groups {
		ordinal, err := parseUint(group.Index, 32, "collector_identity.group.index")
		if err != nil {
			return err
		}
		attributes, err := parseUint(group.AttributesRaw, 32, "collector_identity.group.attributes_raw")
		if err != nil {
			return err
		}
		var nameUse any
		if group.Principal.NameUseRaw != "" {
			parsed, e := parseUint(group.Principal.NameUseRaw, 32, "collector_identity.group.name_use_raw")
			if e != nil {
				return e
			}
			nameUse = int64(parsed)
		}
		_, err = tx.Exec(ctx, `
INSERT INTO fi.collector_token_group (
 source_record_id,group_ordinal,principal_sid,account_name,domain_name,name_use_raw,name_use_name,attributes_raw,
 mandatory,enabled_by_default,enabled,owner,deny_only,integrity,integrity_enabled,logon_id,resource
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
`, sourceRecordID, int(ordinal), group.Principal.SID, nullString(group.Principal.AccountName), nullString(group.Principal.DomainName), nameUse,
			nullString(group.Principal.NameUseName), int64(attributes), group.Mandatory, group.EnabledByDefault, group.Enabled, group.Owner,
			group.DenyOnly, group.Integrity, group.IntegrityEnabled, group.LogonID, group.Resource)
		if err != nil {
			return fmt.Errorf("insert FI collector token group: %w", err)
		}
	}

	for _, privilege := range value.Token.Privileges {
		ordinal, err := parseUint(privilege.Index, 32, "collector_identity.privilege.index")
		if err != nil {
			return err
		}
		low, err := parseUint(privilege.LUIDLow, 32, "collector_identity.privilege.luid_low")
		if err != nil {
			return err
		}
		high, err := parseInt(privilege.LUIDHigh, 32, "collector_identity.privilege.luid_high")
		if err != nil {
			return err
		}
		attributes, err := parseUint(privilege.AttributesRaw, 32, "collector_identity.privilege.attributes_raw")
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO fi.collector_token_privilege (
 source_record_id,privilege_ordinal,luid_low,luid_high,name,attributes_raw,enabled_by_default,enabled,removed,used_for_access
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
`, sourceRecordID, int(ordinal), int64(low), int32(high), nullString(privilege.Name), int64(attributes), privilege.EnabledByDefault,
			privilege.Enabled, privilege.Removed, privilege.UsedForAccess)
		if err != nil {
			return fmt.Errorf("insert FI collector token privilege: %w", err)
		}
	}
	return nil
}

func projectDirectoryPrincipalSnapshot(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.DirectoryPrincipalSnapshot) error {
	observedAt, err := parseRFC3339(value.ObservedAt, "directory_principal_snapshot.observed_at")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO fi.directory_principal_snapshot (source_record_id,observed_at,collection_method,domain_dns_name,server_dns_name,naming_context) VALUES ($1,$2,$3,$4,$5,$6)`,
		sourceRecordID, observedAt, value.CollectionMethod, value.DomainDNSName, value.ServerDNSName, value.NamingContext)
	if err != nil {
		return fmt.Errorf("insert FI directory principal snapshot: %w", err)
	}

	for i, sid := range value.RequestedSIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO fi.directory_requested_sid (source_record_id,sid_ordinal,sid) VALUES ($1,$2,$3)`, sourceRecordID, i+1, sid); err != nil {
			return fmt.Errorf("insert FI directory requested SID: %w", err)
		}
	}
	for i, principal := range value.Principals {
		sidRaw, err := decodeBase64URL(principal.SIDRawBase64URL, true, "directory_principal.sid_raw")
		if err != nil {
			return err
		}
		guidRaw, err := decodeBase64URL(principal.ObjectGUIDRawBase64URL, true, "directory_principal.object_guid_raw")
		if err != nil {
			return err
		}
		if len(guidRaw) != 16 {
			return fmt.Errorf("directory_principal.object_guid_raw must be exactly 16 bytes")
		}
		var uac any
		if principal.UserAccountControlRaw != "" {
			parsed, e := parseUint(principal.UserAccountControlRaw, 32, "directory_principal.user_account_control_raw")
			if e != nil {
				return e
			}
			uac = int64(parsed)
		}
		var primaryGroup any
		if principal.PrimaryGroupIDRaw != "" {
			parsed, e := parseUint(principal.PrimaryGroupIDRaw, 32, "directory_principal.primary_group_id_raw")
			if e != nil {
				return e
			}
			primaryGroup = int64(parsed)
		}
		_, err = tx.Exec(ctx, `
INSERT INTO fi.directory_principal (
 source_record_id,principal_ordinal,sid,sid_raw,object_guid,object_guid_raw,distinguished_name,sam_account_name,user_principal_name,
 user_account_control_raw,account_disabled,primary_group_id_raw
) VALUES ($1,$2,$3,$4,$5::text::uuid,$6,$7,$8,$9,$10,$11,$12)
`, sourceRecordID, i+1, principal.SID, sidRaw, principal.ObjectGUID, guidRaw, principal.DistinguishedName, nullString(principal.SAMAccountName),
			nullString(principal.UserPrincipalName), uac, principal.AccountDisabled, primaryGroup)
		if err != nil {
			return fmt.Errorf("insert FI directory principal: %w", err)
		}
		for classIndex, class := range principal.ObjectClasses {
			if _, err := tx.Exec(ctx, `INSERT INTO fi.directory_principal_class (source_record_id,principal_ordinal,class_ordinal,object_class) VALUES ($1,$2,$3,$4)`, sourceRecordID, i+1, classIndex+1, class); err != nil {
				return fmt.Errorf("insert FI directory principal class: %w", err)
			}
		}
	}
	for i, membership := range value.Memberships {
		if _, err := tx.Exec(ctx, `INSERT INTO fi.directory_membership (source_record_id,membership_ordinal,member_sid,group_sid,source) VALUES ($1,$2,$3,$4,$5)`,
			sourceRecordID, i+1, membership.MemberSID, membership.GroupSID, string(membership.Source)); err != nil {
			return fmt.Errorf("insert FI directory membership: %w", err)
		}
	}
	for i, sid := range value.NotFoundSIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO fi.directory_not_found_sid (source_record_id,sid_ordinal,sid) VALUES ($1,$2,$3)`, sourceRecordID, i+1, sid); err != nil {
			return fmt.Errorf("insert FI directory not-found SID: %w", err)
		}
	}
	return nil
}

func projectLocalPrincipalSnapshot(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.LocalPrincipalSnapshot) error {
	observedAt, err := parseRFC3339(value.ObservedAt, "local_principal_snapshot.observed_at")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO fi.local_principal_snapshot (source_record_id,observed_at,collection_method,computer_name) VALUES ($1,$2,$3,$4)`,
		sourceRecordID, observedAt, value.CollectionMethod, value.ComputerName)
	if err != nil {
		return fmt.Errorf("insert FI local principal snapshot: %w", err)
	}

	for i, user := range value.Users {
		sidRaw, err := decodeBase64URL(user.SIDRawBase64URL, true, "local_user.sid_raw")
		if err != nil {
			return err
		}
		nameRaw, err := decodeBase64URL(user.NameUTF16LEBase64URL, true, "local_user.name_utf16le")
		if err != nil {
			return err
		}
		fullRaw, err := decodeBase64URL(user.FullNameUTF16LEBase64URL, false, "local_user.full_name_utf16le")
		if err != nil {
			return err
		}
		commentRaw, err := decodeBase64URL(user.CommentUTF16LEBase64URL, false, "local_user.comment_utf16le")
		if err != nil {
			return err
		}
		flags, err := parseUint(user.FlagsRaw, 32, "local_user.flags_raw")
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO fi.local_user (
 source_record_id,user_ordinal,sid,sid_raw,name_display,name_utf16le,full_name_display,full_name_utf16le,comment_display,comment_utf16le,
 flags_raw,account_disabled,account_locked
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
`, sourceRecordID, i+1, user.SID, sidRaw, user.NameDisplay, nameRaw, nullString(user.FullNameDisplay), fullRaw, nullString(user.CommentDisplay), commentRaw,
			int64(flags), user.AccountDisabled, user.AccountLocked)
		if err != nil {
			return fmt.Errorf("insert FI local user: %w", err)
		}
	}
	for i, group := range value.Groups {
		sidRaw, err := decodeBase64URL(group.SIDRawBase64URL, true, "local_group.sid_raw")
		if err != nil {
			return err
		}
		nameRaw, err := decodeBase64URL(group.NameUTF16LEBase64URL, true, "local_group.name_utf16le")
		if err != nil {
			return err
		}
		commentRaw, err := decodeBase64URL(group.CommentUTF16LEBase64URL, false, "local_group.comment_utf16le")
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO fi.local_group (
 source_record_id,group_ordinal,sid,sid_raw,account_domain,name_display,name_utf16le,comment_display,comment_utf16le,membership_state,membership_reason_code,membership_detail
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
`, sourceRecordID, i+1, group.SID, sidRaw, nullString(group.AccountDomain), group.NameDisplay, nameRaw, nullString(group.CommentDisplay), commentRaw,
			group.MembershipState, nullString(group.MembershipReasonCode), nullString(group.MembershipDetail))
		if err != nil {
			return fmt.Errorf("insert FI local group: %w", err)
		}
	}
	for i, membership := range value.Memberships {
		memberSIDRaw, err := decodeBase64URL(membership.MemberSIDRawBase64URL, true, "local_group_membership.member_sid_raw")
		if err != nil {
			return err
		}
		memberNameRaw, err := decodeBase64URL(membership.MemberDomainAndNameUTF16LEBase64URL, false, "local_group_membership.member_domain_name_utf16le")
		if err != nil {
			return err
		}
		nameUse, err := parseUint(membership.SIDNameUseRaw, 32, "local_group_membership.sid_name_use_raw")
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO fi.local_group_membership (
 source_record_id,membership_ordinal,group_sid,member_sid,member_sid_raw,member_domain_name_display,member_domain_name_utf16le,sid_name_use_raw,sid_name_use_name
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
`, sourceRecordID, i+1, membership.GroupSID, membership.MemberSID, memberSIDRaw, nullString(membership.MemberDomainAndNameDisplay), memberNameRaw, int64(nameUse), membership.SIDNameUseName)
		if err != nil {
			return fmt.Errorf("insert FI local group membership: %w", err)
		}
	}
	return nil
}

func projectNTFSCollectionError(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value ntfsCollectionErrorPayload) error {
	path, err := decodeBase64URL(value.PathUTF16LEBase64URL, true, "ntfs_collection_error.path_utf16le")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO fi.ntfs_collection_error (source_record_id,path_display,path_utf16le,error_text) VALUES ($1,$2,$3,$4)`, sourceRecordID, value.PathDisplay, path, value.Error)
	if err != nil {
		return fmt.Errorf("insert FI NTFS collection error: %w", err)
	}
	return nil
}

func projectSMBShareSnapshot(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.SMBShareSnapshot) error {
	observedAt, err := parseRFC3339(value.ObservedAt, "smb_share_snapshot.observed_at")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO fi.smb_share_snapshot (source_record_id,observed_at,collection_method) VALUES ($1,$2,$3)`, sourceRecordID, observedAt, string(value.CollectionMethod))
	if err != nil {
		return fmt.Errorf("insert FI SMB share snapshot: %w", err)
	}

	for i, share := range value.Shares {
		ordinal := i + 1
		nameRaw, err := decodeBase64URL(share.NameUTF16LEBase64URL, true, "smb_share.name_utf16le")
		if err != nil {
			return err
		}
		remarkRaw, err := decodeBase64URL(share.RemarkUTF16LEBase64URL, false, "smb_share.remark_utf16le")
		if err != nil {
			return err
		}
		pathRaw, err := decodeBase64URL(share.LocalPathUTF16LEBase64URL, false, "smb_share.local_path_utf16le")
		if err != nil {
			return err
		}
		typeRaw, err := parseUint(share.TypeRaw, 32, "smb_share.type_raw")
		if err != nil {
			return err
		}
		permissions, err := parseUint(share.PermissionsRaw, 32, "smb_share.permissions_raw")
		if err != nil {
			return err
		}
		maxUses, err := parseUint(share.MaxUsesRaw, 32, "smb_share.max_uses_raw")
		if err != nil {
			return err
		}
		currentUses, err := parseUint(share.CurrentUses, 32, "smb_share.current_uses")
		if err != nil {
			return err
		}
		securityRaw, err := decodeBase64URL(share.Security.RawDescriptorBase64URL, false, "smb_share.security.raw_descriptor")
		if err != nil {
			return err
		}
		revision, err := optionalUintValue(share.Security.Revision, 8, "smb_share.security.revision")
		if err != nil {
			return err
		}
		control, err := optionalUintValue(share.Security.Control, 16, "smb_share.security.control")
		if err != nil {
			return err
		}
		aclRevision, err := optionalUintValue(share.Security.DACL.Revision, 8, "smb_share.security.dacl.revision")
		if err != nil {
			return err
		}
		aclSize, err := optionalUintValue(share.Security.DACL.Size, 32, "smb_share.security.dacl.size")
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO fi.smb_share (
 source_record_id,share_ordinal,name_display,name_utf16le,type_raw,type_name,special,temporary,remark_display,remark_utf16le,local_path_display,local_path_utf16le,
 permissions_raw,max_uses_raw,current_uses,security_state,security_data_format,security_raw_descriptor,security_revision,security_control,security_owner_sid,
 security_primary_group_sid,dacl_state,dacl_revision,dacl_size,security_reason_code
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
`, sourceRecordID, ordinal, share.NameDisplay, nameRaw, int64(typeRaw), string(share.TypeName), share.Special, share.Temporary,
			nullString(share.RemarkDisplay), remarkRaw, nullString(share.LocalPathDisplay), pathRaw, int64(permissions), int64(maxUses), int64(currentUses),
			string(share.Security.State), string(share.Security.DataFormat), securityRaw, revision, control, nullString(share.Security.OwnerSID),
			nullString(share.Security.PrimaryGroupSID), nullString(string(share.Security.DACL.State)), aclRevision, aclSize, nullString(share.Security.ReasonCode))
		if err != nil {
			return fmt.Errorf("insert FI SMB share: %w", err)
		}

		for _, ace := range share.Security.DACL.ACEs {
			if err := projectSMBShareACE(ctx, tx, sourceRecordID, ordinal, ace); err != nil {
				return err
			}
		}
	}
	return nil
}

func projectSMBShareACE(ctx context.Context, tx pgx.Tx, sourceRecordID int64, shareOrdinal int, value records.ACEObservation) error {
	ordinal, err := parseUint(value.Index, 32, "smb_share_ace.index")
	if err != nil {
		return err
	}
	aceType, err := parseUint(value.Type, 8, "smb_share_ace.type")
	if err != nil {
		return err
	}
	flags, err := parseUint(value.Flags, 8, "smb_share_ace.flags")
	if err != nil {
		return err
	}
	size, err := parseUint(value.Size, 16, "smb_share_ace.size")
	if err != nil {
		return err
	}
	raw, err := decodeBase64URL(value.RawBase64URL, true, "smb_share_ace.raw")
	if err != nil {
		return err
	}
	mask, err := optionalUintValue(value.Mask, 32, "smb_share_ace.mask")
	if err != nil {
		return err
	}
	objectFlags, err := optionalUintValue(value.ObjectFlags, 32, "smb_share_ace.object_flags")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.smb_share_ace (
 source_record_id,share_ordinal,ace_ordinal,ace_type,type_name,flags,ace_size,raw_ace,access_mask,object_flags,object_type_guid,inherited_object_type_guid,sid
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::text::uuid,$12::text::uuid,$13)
`, sourceRecordID, shareOrdinal, int(ordinal), int(aceType), value.TypeName, int(flags), int(size), raw, mask, objectFlags,
		nullString(value.ObjectTypeGUID), nullString(value.InheritedObjectTypeGUID), nullString(value.SID))
	if err != nil {
		return fmt.Errorf("insert FI SMB share ACE: %w", err)
	}
	return nil
}

func projectSupportingSourceCollectionError(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value supportingSourceCollectionErrorPayload) error {
	_, err := tx.Exec(ctx, `INSERT INTO fi.supporting_source_collection_error (source_record_id,source,error_text) VALUES ($1,$2,$3)`, sourceRecordID, value.Source, value.Error)
	if err != nil {
		return fmt.Errorf("insert FI supporting-source collection error: %w", err)
	}
	return nil
}
