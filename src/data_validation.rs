// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Generic CSV schema registry and validator.

use std::collections::HashMap;

use serde::Serialize;
use utoipa::ToSchema;

/// Maximum number of validation errors returned per request.
pub const MAX_VALIDATION_ERRORS: usize = 100;

/// Built-in schema used by the pilot while keeping API generic.
pub const DEFAULT_SCHEMA_ID: &str = "pilot_v1";

/// Field type constraints supported by the CSV validator.
#[derive(Debug, Clone)]
pub enum FieldType {
    Char(usize),
    Varchar(usize),
    Integer,
    Decimal { precision: u8, scale: u8 },
    DateDdMmYyyy,
    Flag01,
}

/// Schema definition for a single CSV column.
#[derive(Debug, Clone)]
pub struct FieldSchema {
    pub name: &'static str,
    pub field_type: FieldType,
    pub nullable: bool,
}

/// One validation error in a CSV file.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ValidationError {
    /// Data row number (1-indexed, excludes header row).
    pub row: usize,
    /// Column name.
    pub field: String,
    /// Human-readable validation error.
    pub message: String,
}

/// Validation output for CSV pre-checks and upload gating.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ValidationSummary {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub rows_validated: usize,
}

/// Return the schema for a logical `schema_id`.
///
/// The API is generic and schema-based; pilot currently ships with one schema.
pub fn schema_for_id(schema_id: &str) -> Option<Vec<FieldSchema>> {
    match schema_id {
        DEFAULT_SCHEMA_ID | "default" => Some(default_pilot_schema()),
        _ => None,
    }
}

/// Return supported schema IDs for API error messages.
pub fn supported_schema_ids() -> Vec<&'static str> {
    vec![DEFAULT_SCHEMA_ID, "default"]
}

/// Validate CSV bytes against a given schema.
pub fn validate_csv_bytes(data: &[u8], schema: &[FieldSchema]) -> ValidationSummary {
    let mut errors = Vec::new();
    let mut rows_validated = 0usize;

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(data);

    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(_) => {
            errors.push(ValidationError {
                row: 0,
                field: "header".to_string(),
                message: "Could not parse CSV headers".to_string(),
            });
            return ValidationSummary {
                valid: false,
                errors,
                rows_validated,
            };
        }
    };

    let mut header_to_index = HashMap::new();
    for (idx, header) in headers.iter().enumerate() {
        header_to_index.insert(header, idx);
    }

    for field in schema {
        if !header_to_index.contains_key(field.name) {
            errors.push(ValidationError {
                row: 0,
                field: field.name.to_string(),
                message: format!("Missing required column: {}", field.name),
            });
            if errors.len() >= MAX_VALIDATION_ERRORS {
                return ValidationSummary {
                    valid: false,
                    errors,
                    rows_validated,
                };
            }
        }
    }

    for (row_idx, row_result) in reader.records().enumerate() {
        if errors.len() >= MAX_VALIDATION_ERRORS {
            break;
        }

        let record = match row_result {
            Ok(record) => record,
            Err(_) => {
                errors.push(ValidationError {
                    row: row_idx + 1,
                    field: "row".to_string(),
                    message: "Malformed CSV row".to_string(),
                });
                continue;
            }
        };

        rows_validated += 1;

        for field in schema {
            if errors.len() >= MAX_VALIDATION_ERRORS {
                break;
            }

            let Some(col_idx) = header_to_index.get(field.name) else {
                continue;
            };

            let value = record.get(*col_idx).unwrap_or("").trim();
            if let Some(message) = validate_field_value(value, field) {
                errors.push(ValidationError {
                    row: row_idx + 1,
                    field: field.name.to_string(),
                    message,
                });
            }
        }

        // Detect records with fewer fields than declared by headers.
        if record.len() < headers.len() && errors.len() < MAX_VALIDATION_ERRORS {
            errors.push(ValidationError {
                row: row_idx + 1,
                field: "row".to_string(),
                message: "Row has fewer columns than header".to_string(),
            });
        }
    }

    ValidationSummary {
        valid: errors.is_empty(),
        errors,
        rows_validated,
    }
}

fn validate_field_value(value: &str, field: &FieldSchema) -> Option<String> {
    if value.is_empty() {
        return if field.nullable {
            None
        } else {
            Some("field is required".to_string())
        };
    }

    match field.field_type {
        FieldType::Char(max) | FieldType::Varchar(max) => {
            let len = value.chars().count();
            if len > max {
                Some(format!("Maximum length is {max} characters, got {len}"))
            } else {
                None
            }
        }
        FieldType::Integer => match value.parse::<i64>() {
            Ok(_) => None,
            Err(_) => Some(format!("Must be an integer, got '{value}'")),
        },
        FieldType::Decimal { precision, scale } => validate_decimal(value, precision, scale),
        FieldType::DateDdMmYyyy => validate_date_dd_mm_yyyy(value),
        FieldType::Flag01 => {
            if matches!(value, "0" | "1") {
                None
            } else {
                Some(format!("Must be '0' or '1', got '{value}'"))
            }
        }
    }
}

fn validate_decimal(value: &str, precision: u8, scale: u8) -> Option<String> {
    if value.contains('e') || value.contains('E') {
        return Some(format!("Scientific notation is not allowed, got '{value}'"));
    }

    if value.parse::<f64>().is_err() {
        return Some(format!("Must be a decimal number, got '{value}'"));
    }

    let value = value.trim_start_matches(['+', '-']);
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() > 2 {
        return Some(format!("Invalid decimal format, got '{value}'"));
    }
    if parts
        .iter()
        .any(|part| !part.chars().all(|c| c.is_ascii_digit()))
    {
        return Some(format!("Invalid decimal format, got '{value}'"));
    }

    let decimals = if parts.len() == 2 { parts[1].len() } else { 0 };
    if decimals > scale as usize {
        return Some(format!("Maximum {scale} decimal places, got {decimals}"));
    }

    let total_digits: usize = value.chars().filter(|c| c.is_ascii_digit()).count();
    if total_digits > precision as usize {
        return Some(format!(
            "Maximum {precision} total digits, got {total_digits}"
        ));
    }

    None
}

fn validate_date_dd_mm_yyyy(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[2] != b'/' || bytes[5] != b'/' {
        return Some(format!("Date must be in DD/MM/YYYY format, got '{value}'"));
    }
    if !bytes[0..2].iter().all(u8::is_ascii_digit)
        || !bytes[3..5].iter().all(u8::is_ascii_digit)
        || !bytes[6..10].iter().all(u8::is_ascii_digit)
    {
        return Some(format!("Date must be in DD/MM/YYYY format, got '{value}'"));
    }

    // Use chrono for proper calendar validation (leap years, month-specific day limits).
    let reformatted = format!("{}-{}-{}", &value[6..10], &value[3..5], &value[0..2]);
    match chrono::NaiveDate::parse_from_str(&reformatted, "%Y-%m-%d") {
        Ok(_) => None,
        Err(_) => Some(format!("Invalid calendar date, got '{value}'")),
    }
}

fn default_pilot_schema() -> Vec<FieldSchema> {
    vec![
        FieldSchema {
            name: "description",
            field_type: FieldType::Char(5),
            nullable: true,
        },
        FieldSchema {
            name: "externalTypeId",
            field_type: FieldType::Integer,
            nullable: false,
        },
        FieldSchema {
            name: "privacy",
            field_type: FieldType::Flag01,
            nullable: true,
        },
        FieldSchema {
            name: "issuingBody",
            field_type: FieldType::Char(3),
            nullable: true,
        },
        FieldSchema {
            name: "memberBody",
            field_type: FieldType::Char(3),
            nullable: true,
        },
        FieldSchema {
            name: "awardBoardDate",
            field_type: FieldType::DateDdMmYyyy,
            nullable: true,
        },
        FieldSchema {
            name: "awardGpaValue",
            field_type: FieldType::Decimal {
                precision: 10,
                scale: 2,
            },
            nullable: true,
        },
        FieldSchema {
            name: "awardResult",
            field_type: FieldType::Varchar(100),
            nullable: false,
        },
        FieldSchema {
            name: "awardName",
            field_type: FieldType::Varchar(240),
            nullable: true,
        },
        FieldSchema {
            name: "awardMajorCode",
            field_type: FieldType::Varchar(50),
            nullable: true,
        },
        FieldSchema {
            name: "awardProgrammeCode",
            field_type: FieldType::Varchar(50),
            nullable: true,
        },
        FieldSchema {
            name: "awardYear",
            field_type: FieldType::Varchar(9),
            nullable: true,
        },
        FieldSchema {
            name: "awardType",
            field_type: FieldType::Integer,
            nullable: true,
        },
        FieldSchema {
            name: "updated_at",
            field_type: FieldType::DateDdMmYyyy,
            nullable: true,
        },
        FieldSchema {
            name: "created_at",
            field_type: FieldType::DateDdMmYyyy,
            nullable: true,
        },
        FieldSchema {
            name: "is_deleted",
            field_type: FieldType::Flag01,
            nullable: true,
        },
        FieldSchema {
            name: "azureId",
            field_type: FieldType::Varchar(36),
            nullable: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_csv() -> String {
        [
            "description,externalTypeId,privacy,issuingBody,memberBody,awardBoardDate,awardGpaValue,awardResult,awardName,awardMajorCode,awardProgrammeCode,awardYear,awardType,updated_at,created_at,is_deleted,azureId",
            "DESC1,10,1,ISS,MB1,01/02/2025,9.50,PASS,Award Name,MAJOR,PROG,2024/2025,2,01/02/2025,01/02/2025,0,123e4567-e89b-12d3-a456-426614174000",
        ]
        .join("\n")
    }

    #[test]
    fn validates_happy_path() {
        let schema = schema_for_id(DEFAULT_SCHEMA_ID).expect("schema should exist");
        let result = validate_csv_bytes(valid_csv().as_bytes(), &schema);
        assert!(result.valid, "expected valid CSV, got: {:?}", result.errors);
        assert_eq!(result.rows_validated, 1);
    }

    #[test]
    fn rejects_missing_required_column() {
        let csv = "externalTypeId,awardResult\n1,PASS\n";
        let schema = schema_for_id(DEFAULT_SCHEMA_ID).expect("schema should exist");
        let result = validate_csv_bytes(csv.as_bytes(), &schema);
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.starts_with("Missing required column")));
    }

    #[test]
    fn rejects_required_field_empty() {
        let csv = [
            "description,externalTypeId,privacy,issuingBody,memberBody,awardBoardDate,awardGpaValue,awardResult,awardName,awardMajorCode,awardProgrammeCode,awardYear,awardType,updated_at,created_at,is_deleted,azureId",
            ",,1,,,,,,Name,,,,,,,0,",
        ]
        .join("\n");
        let schema = schema_for_id(DEFAULT_SCHEMA_ID).expect("schema should exist");
        let result = validate_csv_bytes(csv.as_bytes(), &schema);
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "externalTypeId" && e.message == "field is required"));
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "awardResult" && e.message == "field is required"));
    }

    #[test]
    fn rejects_bad_decimal_scale() {
        let csv = [
            "description,externalTypeId,privacy,issuingBody,memberBody,awardBoardDate,awardGpaValue,awardResult,awardName,awardMajorCode,awardProgrammeCode,awardYear,awardType,updated_at,created_at,is_deleted,azureId",
            "A,1,1,ISS,MB1,01/02/2025,9.999,PASS,Name,MAJOR,PROG,2024,2,01/02/2025,01/02/2025,0,id",
        ]
        .join("\n");
        let schema = schema_for_id(DEFAULT_SCHEMA_ID).expect("schema should exist");
        let result = validate_csv_bytes(csv.as_bytes(), &schema);
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "awardGpaValue" && e.message.contains("decimal places")));
    }

    #[test]
    fn rejects_bad_date() {
        let csv = [
            "description,externalTypeId,privacy,issuingBody,memberBody,awardBoardDate,awardGpaValue,awardResult,awardName,awardMajorCode,awardProgrammeCode,awardYear,awardType,updated_at,created_at,is_deleted,azureId",
            "A,1,1,ISS,MB1,32/13/2025,9.50,PASS,Name,MAJOR,PROG,2024,2,01/02/2025,01/02/2025,0,id",
        ]
        .join("\n");
        let schema = schema_for_id(DEFAULT_SCHEMA_ID).expect("schema should exist");
        let result = validate_csv_bytes(csv.as_bytes(), &schema);
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "awardBoardDate" && e.message.contains("Invalid calendar date")));
    }
}
