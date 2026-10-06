//! JSON Schema for an input file, generated from the factor catalog.
//!
//! This is the contract a coding agent reads before producing input, so it
//! never has to guess a field name or a score range.

use crate::model::catalog::{FACTORS, MAX_SCORE};
use serde_json::{json, Map, Value};

pub fn schema() -> Value {
    let mut factor_properties = Map::new();

    for factor in FACTORS {
        let anchors: Vec<Value> = factor
            .anchors
            .iter()
            .map(|(score, label)| json!({ "score": score, "option": label }))
            .collect();

        factor_properties.insert(
            factor.key.to_string(),
            json!({
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_SCORE,
                "title": factor.name,
                "description": format!(
                    "{} ({}). Scores between two anchored options are accepted \
                     as interpolation.",
                    factor.name,
                    factor.group.title()
                ),
                "x-group": factor.group,
                "x-anchors": anchors,
            }),
        );
    }

    let required: Vec<&str> = FACTORS.iter().map(|factor| factor.key).collect();

    let threat = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["title", "factors"],
        "properties": {
            "title": {
                "type": "string",
                "minLength": 1,
                "description": "Threat name as it appears in the threat table."
            },
            "id": {
                "type": "string",
                "description": "Stable identifier. Defaults to a slug of the title."
            },
            "notes": {
                "type": "string",
                "description": "Free-text note carried into the report."
            },
            "location": {
                "type": "string",
                "description": "Artifact or code location, carried into SARIF output."
            },
            "factors": {
                "type": "object",
                "additionalProperties": false,
                "description": "Every factor scored 0 to 9. A score of 0 is a real \
                                score and counts toward its average; it does not mean \
                                unscored. Omitting a factor is an error unless \
                                --allow-missing is passed.",
                "required": required,
                "properties": Value::Object(factor_properties),
            }
        }
    });

    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/gbiagomba/OWASP-Risk-Rating-Methodology/schema/v1",
        "title": "riskforge input",
        "description": "Input for riskforge, which scores threats with the OWASP \
                        Risk Rating Methodology. Accepts a single threat object, an \
                        array of threat objects, or an object with a `threats` array.",
        "oneOf": [
            { "$ref": "#/$defs/threat" },
            { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/threat" } },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["threats"],
                "properties": {
                    "threats": {
                        "type": "array",
                        "minItems": 1,
                        "items": { "$ref": "#/$defs/threat" }
                    }
                }
            }
        ],
        "$defs": { "threat": threat }
    })
}
