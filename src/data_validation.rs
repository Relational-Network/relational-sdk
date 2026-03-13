// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Generic CSV schema registry and validator.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Maximum number of validation errors returned per request.
pub const MAX_VALIDATION_ERRORS: usize = 100;

/// Field type constraints supported by the CSV validator.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Char(usize),
    Varchar(usize),
    Integer,
    Decimal { precision: u8, scale: u8 },
    DateDdMmYyyy,
    Flag01,
}

/// Schema definition for a single CSV column.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FieldSchema {
    pub name: String,
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

/// Load a schema from disk at `{data_dir}/schemas/{schema_id}.json`.
///
/// Returns `None` if the schema file does not exist or cannot be parsed.
pub fn schema_for_id(schema_id: &str, data_dir: &Path) -> Option<Vec<FieldSchema>> {
    let schema_path = data_dir.join("schemas").join(format!("{schema_id}.json"));
    let content = std::fs::read_to_string(&schema_path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Persist a schema definition to `{data_dir}/schemas/{schema_id}.json`.
///
/// Creates the `schemas/` directory if it does not exist.
pub fn save_schema(schema_id: &str, schema: &[FieldSchema], data_dir: &Path) -> Result<(), String> {
    let schemas_dir = data_dir.join("schemas");
    std::fs::create_dir_all(&schemas_dir)
        .map_err(|e| format!("failed to create schemas directory: {e}"))?;
    let schema_path = schemas_dir.join(format!("{schema_id}.json"));
    let json = serde_json::to_string_pretty(schema)
        .map_err(|e| format!("failed to serialize schema: {e}"))?;
    std::fs::write(&schema_path, json).map_err(|e| format!("failed to write schema file: {e}"))?;
    Ok(())
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
        if !header_to_index.contains_key(field.name.as_str()) {
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

            let Some(col_idx) = header_to_index.get(field.name.as_str()) else {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only helper: returns the pilot_v1 schema for validation tests.
    fn test_pilot_schema() -> Vec<FieldSchema> {
        vec![
            FieldSchema {
                name: "description".into(),
                field_type: FieldType::Char(5),
                nullable: true,
            },
            FieldSchema {
                name: "externalTypeId".into(),
                field_type: FieldType::Integer,
                nullable: false,
            },
            FieldSchema {
                name: "privacy".into(),
                field_type: FieldType::Flag01,
                nullable: true,
            },
            FieldSchema {
                name: "issuingBody".into(),
                field_type: FieldType::Char(3),
                nullable: true,
            },
            FieldSchema {
                name: "memberBody".into(),
                field_type: FieldType::Char(3),
                nullable: true,
            },
            FieldSchema {
                name: "awardBoardDate".into(),
                field_type: FieldType::DateDdMmYyyy,
                nullable: true,
            },
            FieldSchema {
                name: "awardGpaValue".into(),
                field_type: FieldType::Decimal {
                    precision: 10,
                    scale: 2,
                },
                nullable: true,
            },
            FieldSchema {
                name: "awardResult".into(),
                field_type: FieldType::Varchar(100),
                nullable: false,
            },
            FieldSchema {
                name: "awardName".into(),
                field_type: FieldType::Varchar(240),
                nullable: true,
            },
            FieldSchema {
                name: "awardMajorCode".into(),
                field_type: FieldType::Varchar(50),
                nullable: true,
            },
            FieldSchema {
                name: "awardProgrammeCode".into(),
                field_type: FieldType::Varchar(50),
                nullable: true,
            },
            FieldSchema {
                name: "awardYear".into(),
                field_type: FieldType::Varchar(9),
                nullable: true,
            },
            FieldSchema {
                name: "awardType".into(),
                field_type: FieldType::Integer,
                nullable: true,
            },
            FieldSchema {
                name: "updated_at".into(),
                field_type: FieldType::DateDdMmYyyy,
                nullable: true,
            },
            FieldSchema {
                name: "created_at".into(),
                field_type: FieldType::DateDdMmYyyy,
                nullable: true,
            },
            FieldSchema {
                name: "is_deleted".into(),
                field_type: FieldType::Flag01,
                nullable: true,
            },
            FieldSchema {
                name: "azureId".into(),
                field_type: FieldType::Varchar(36),
                nullable: true,
            },
        ]
    }

    fn valid_csv() -> String {
        [
            "description,externalTypeId,privacy,issuingBody,memberBody,awardBoardDate,awardGpaValue,awardResult,awardName,awardMajorCode,awardProgrammeCode,awardYear,awardType,updated_at,created_at,is_deleted,azureId",
            "DESC1,10,1,ISS,MB1,01/02/2025,9.50,PASS,Award Name,MAJOR,PROG,2024/2025,2,01/02/2025,01/02/2025,0,123e4567-e89b-12d3-a456-426614174000",
        ]
        .join("\n")
    }

    #[test]
    fn validates_happy_path() {
        let schema = test_pilot_schema();
        let result = validate_csv_bytes(valid_csv().as_bytes(), &schema);
        assert!(result.valid, "expected valid CSV, got: {:?}", result.errors);
        assert_eq!(result.rows_validated, 1);
    }

    #[test]
    fn rejects_missing_required_column() {
        let csv = "externalTypeId,awardResult\n1,PASS\n";
        let schema = test_pilot_schema();
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
        let schema = test_pilot_schema();
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
        let schema = test_pilot_schema();
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
        let schema = test_pilot_schema();
        let result = validate_csv_bytes(csv.as_bytes(), &schema);
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "awardBoardDate" && e.message.contains("Invalid calendar date")));
    }

    #[test]
    fn round_trips_schema_through_json() {
        let schema = test_pilot_schema();
        let json = serde_json::to_string(&schema).expect("serialize");
        let loaded: Vec<FieldSchema> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(loaded.len(), schema.len());
        assert_eq!(loaded[0].name, "description");
    }

    #[test]
    fn save_and_load_schema_from_disk() {
        let dir = std::env::temp_dir().join(format!("schema_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let schema = test_pilot_schema();
        save_schema("test_v1", &schema, &dir).expect("save");
        let loaded = schema_for_id("test_v1", &dir).expect("load");
        assert_eq!(loaded.len(), schema.len());
        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
