//! Generated HTTP API description for docs and integrators.
//!
//! The server remains the implementation source of truth; this module keeps the
//! documented route shapes in Rust so CI can regenerate the committed OpenAPI
//! artifact and catch drift.

use serde_json::{Value, json};

/// Return the OpenAPI document for the shipped HTTP surface.
pub fn spec() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "openKMS HTTP API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "YubiHSM2-backed transaction signer for Cosmos and Solana."
        },
        "servers": [
            {
                "url": "http://127.0.0.1:9443",
                "description": "Default loopback deployment"
            }
        ],
        "tags": [
            { "name": "health" },
            { "name": "keys" },
            { "name": "signing" },
            { "name": "admin" },
            { "name": "metrics" }
        ],
        "paths": {
            "/health": {
                "get": {
                    "tags": ["health"],
                    "summary": "Report service and HSM health",
                    "operationId": "getHealth",
                    "responses": {
                        "200": {
                            "description": "The service is reachable.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Health" }
                                }
                            }
                        }
                    }
                }
            },
            "/keys": {
                "get": {
                    "tags": ["keys"],
                    "summary": "List configured signing keys",
                    "operationId": "listKeys",
                    "responses": {
                        "200": {
                            "description": "Configured keys with derived addresses and enabled state.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": { "$ref": "#/components/schemas/KeySummary" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/policy": {
                "get": {
                    "tags": ["signing"],
                    "summary": "List effective signing policies and live usage",
                    "operationId": "listPolicy",
                    "security": [{ "signerBearer": [] }],
                    "responses": policy_list_responses()
                }
            },
            "/policy/{label}": {
                "get": {
                    "tags": ["signing"],
                    "summary": "Get effective signing policy and live usage for a key",
                    "operationId": "getPolicy",
                    "security": [{ "signerBearer": [] }],
                    "parameters": [key_label_parameter()],
                    "responses": policy_get_responses()
                }
            },
            "/sign/solana": {
                "post": {
                    "tags": ["signing"],
                    "summary": "Sign a Solana VersionedMessage",
                    "operationId": "signSolana",
                    "security": [{ "signerBearer": [] }],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/SolanaSignRequest" }
                            }
                        }
                    },
                    "responses": signed_responses()
                }
            },
            "/sign/cosmos": {
                "post": {
                    "tags": ["signing"],
                    "summary": "Sign a Cosmos SDK SignDoc",
                    "operationId": "signCosmos",
                    "security": [{ "signerBearer": [] }],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/CosmosSignRequest" }
                            }
                        }
                    },
                    "responses": signed_responses()
                }
            },
            "/admin/keys/{label}/enable": {
                "post": {
                    "tags": ["admin"],
                    "summary": "Enable a configured key",
                    "operationId": "enableKey",
                    "security": [{ "adminBearer": [] }],
                    "parameters": [key_label_parameter()],
                    "responses": admin_responses()
                }
            },
            "/admin/keys/{label}/disable": {
                "post": {
                    "tags": ["admin"],
                    "summary": "Disable a configured key",
                    "operationId": "disableKey",
                    "security": [{ "adminBearer": [] }],
                    "parameters": [key_label_parameter()],
                    "responses": admin_responses()
                }
            },
            "/admin/policy": {
                "get": {
                    "tags": ["admin"],
                    "summary": "List policy snapshots with admin overlay metadata",
                    "operationId": "adminListPolicy",
                    "security": [{ "adminBearer": [] }],
                    "responses": policy_list_responses()
                }
            },
            "/admin/keys/{label}/policy": {
                "get": {
                    "tags": ["admin"],
                    "summary": "Get a key policy snapshot with admin overlay metadata",
                    "operationId": "adminGetPolicy",
                    "security": [{ "adminBearer": [] }],
                    "parameters": [key_label_parameter()],
                    "responses": policy_get_responses()
                },
                "patch": {
                    "tags": ["admin"],
                    "summary": "Patch a persisted per-key policy overlay",
                    "operationId": "adminPatchPolicy",
                    "security": [{ "adminBearer": [] }],
                    "parameters": [key_label_parameter()],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/KeyPolicyPatch" }
                            }
                        }
                    },
                    "responses": admin_policy_mutation_responses()
                },
                "delete": {
                    "tags": ["admin"],
                    "summary": "Clear the persisted per-key policy overlay",
                    "operationId": "adminDeletePolicy",
                    "security": [{ "adminBearer": [] }],
                    "parameters": [key_label_parameter()],
                    "responses": admin_policy_mutation_responses()
                }
            },
            "/metrics": {
                "get": {
                    "tags": ["metrics"],
                    "summary": "Expose Prometheus metrics",
                    "operationId": "getMetrics",
                    "responses": {
                        "200": {
                            "description": "Prometheus text exposition.",
                            "content": {
                                "text/plain": {
                                    "schema": {
                                        "type": "string",
                                        "examples": [
                                            "openkms_signs_total{chain=\"solana\",label=\"solana-hot-0\",result=\"allow\"} 1"
                                        ]
                                    }
                                }
                            }
                        },
                        "500": { "$ref": "#/components/responses/InternalError" }
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "signerBearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Bearer token loaded from signer_token_file."
                },
                "adminBearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Bearer token loaded from admin_token_file."
                }
            },
            "schemas": {
                "Health": {
                    "type": "object",
                    "required": ["status", "vault_up"],
                    "properties": {
                        "status": {
                            "type": "string",
                            "const": "ok"
                        },
                        "vault_up": {
                            "type": ["boolean", "null"],
                            "description": "Null on the first response after process start; boolean thereafter."
                        }
                    }
                },
                "KeySummary": {
                    "type": "object",
                    "required": ["label", "chain", "address", "enabled", "vault", "key_id", "derivation_path"],
                    "properties": {
                        "label": { "type": "string" },
                        "chain": {
                            "type": "string",
                            "enum": ["solana", "cosmos", "unknown"]
                        },
                        "address": { "type": "string" },
                        "enabled": { "type": "boolean" },
                        "vault": { "type": "string" },
                        "key_id": { "type": "string" },
                        "derivation_path": {
                            "type": ["string", "null"],
                            "examples": ["m/44'/118'/0'/0/0"]
                        }
                    }
                },
                "SolanaSignRequest": {
                    "type": "object",
                    "required": ["label", "message_b64"],
                    "properties": {
                        "label": { "type": "string" },
                        "expected_chain_id": {
                            "type": "string",
                            "description": "Optional audit/log context; Solana messages do not embed chain id."
                        },
                        "message_b64": {
                            "type": "string",
                            "description": "Base64-encoded Solana VersionedMessage."
                        },
                        "address_lookup_tables": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/SolanaAddressLookupTable" },
                            "default": []
                        }
                    },
                    "additionalProperties": false
                },
                "SolanaAddressLookupTable": {
                    "type": "object",
                    "required": ["key", "addresses"],
                    "properties": {
                        "key": { "type": "string" },
                        "addresses": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    },
                    "additionalProperties": false
                },
                "CosmosSignRequest": {
                    "type": "object",
                    "required": ["label", "sign_doc_b64", "expected_chain_id"],
                    "properties": {
                        "label": { "type": "string" },
                        "sign_doc_b64": {
                            "type": "string",
                            "description": "Base64-encoded cosmos.tx.v1beta1.SignDoc."
                        },
                        "expected_chain_id": {
                            "type": "string",
                            "description": "Must match the chain_id inside the decoded SignDoc."
                        }
                    },
                    "additionalProperties": false
                },
                "SignResponse": {
                    "type": "object",
                    "required": ["signature_b64"],
                    "properties": {
                        "signature_b64": {
                            "type": "string",
                            "description": "Base64-encoded 64-byte signature."
                        }
                    }
                },
                "AdminKeyResponse": {
                    "type": "object",
                    "required": ["label", "enabled"],
                    "properties": {
                        "label": { "type": "string" },
                        "enabled": { "type": "boolean" }
                    }
                },
                "PolicySnapshot": {
                    "type": "object",
                    "required": ["label", "chain", "address", "vault", "key_id", "derivation_path", "effective_enabled", "policy", "runtime"],
                    "properties": {
                        "label": { "type": "string" },
                        "chain": {
                            "type": "string",
                            "enum": ["solana", "cosmos", "unknown"]
                        },
                        "address": { "type": "string" },
                        "vault": { "type": "string" },
                        "key_id": { "type": "string" },
                        "derivation_path": { "type": ["string", "null"] },
                        "effective_enabled": { "type": "boolean" },
                        "policy": { "$ref": "#/components/schemas/KeyPolicy" },
                        "runtime": { "$ref": "#/components/schemas/PolicyRuntime" },
                        "policy_source": {
                            "type": "string",
                            "enum": ["config", "config+overlay"],
                            "description": "Admin responses only."
                        },
                        "baseline_policy": {
                            "$ref": "#/components/schemas/KeyPolicy",
                            "description": "Admin responses only."
                        },
                        "overlay": {
                            "$ref": "#/components/schemas/KeyPolicyPatch",
                            "description": "Admin responses only."
                        }
                    }
                },
                "KeyPolicy": {
                    "type": "object",
                    "properties": key_policy_properties()
                },
                "KeyPolicyPatch": {
                    "type": "object",
                    "description": "Partial overlay. Non-null fields present in a PATCH replace the corresponding baseline policy field.",
                    "properties": key_policy_properties()
                },
                "AllowedProgram": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": { "type": "string" },
                        "comment": { "type": ["string", "null"] }
                    }
                },
                "AllowedMessage": {
                    "type": "object",
                    "required": ["type_url"],
                    "properties": {
                        "type_url": { "type": "string" },
                        "per_tx_cap": {
                            "type": ["object", "null"],
                            "additionalProperties": { "type": "string" }
                        },
                        "allowed_recipients": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "allowed_contracts": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "allowed_methods": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "comment": { "type": ["string", "null"] }
                    }
                },
                "AllowedRecipient": {
                    "type": "object",
                    "required": ["program", "addresses"],
                    "properties": {
                        "program": { "type": "string" },
                        "addresses": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    }
                },
                "PolicyRuntime": {
                    "type": "object",
                    "required": ["effective_enabled", "enabled_override", "daily_spend", "sign_counts"],
                    "properties": {
                        "effective_enabled": { "type": "boolean" },
                        "enabled_override": { "type": ["boolean", "null"] },
                        "daily_spend": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/DailySpend" }
                        },
                        "sign_counts": { "$ref": "#/components/schemas/SignCounts" }
                    }
                },
                "DailySpend": {
                    "type": "object",
                    "required": ["token", "day_unix", "spent", "cap"],
                    "properties": {
                        "token": { "type": "string" },
                        "day_unix": { "type": "integer" },
                        "spent": { "type": "string" },
                        "cap": { "type": ["string", "null"] }
                    }
                },
                "SignCounts": {
                    "type": "object",
                    "properties": {
                        "per_minute": { "$ref": "#/components/schemas/WindowSignCount" },
                        "per_hour": { "$ref": "#/components/schemas/WindowSignCount" },
                        "per_day": { "$ref": "#/components/schemas/WindowSignCount" }
                    }
                },
                "WindowSignCount": {
                    "type": "object",
                    "required": ["limit", "used", "window_secs"],
                    "properties": {
                        "limit": { "type": "integer", "minimum": 0 },
                        "used": { "type": "integer", "minimum": 0 },
                        "window_secs": { "type": "integer", "minimum": 1 }
                    }
                },
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": { "type": "string" }
                    }
                }
            },
            "responses": {
                "BadRequest": error_response("Request payload could not be decoded or validated."),
                "Unauthorized": error_response("Bearer token is missing or invalid."),
                "Forbidden": error_response("Policy denied the request."),
                "NotFound": error_response("Requested key label was not found."),
                "RateLimited": error_response("Rate-limit policy denied the request."),
                "InternalError": error_response("Internal server or HSM error.")
            }
        }
    })
}

/// Return the OpenAPI document formatted exactly as committed in `openapi/`.
pub fn spec_json_pretty() -> String {
    let mut out = serde_json::to_string_pretty(&spec()).expect("OpenAPI spec serializes");
    out.push('\n');
    out
}

fn signed_responses() -> Value {
    json!({
        "200": {
            "description": "Signature produced or returned from replay cache.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/SignResponse" }
                }
            }
        },
        "400": { "$ref": "#/components/responses/BadRequest" },
        "401": { "$ref": "#/components/responses/Unauthorized" },
        "403": { "$ref": "#/components/responses/Forbidden" },
        "404": { "$ref": "#/components/responses/NotFound" },
        "429": { "$ref": "#/components/responses/RateLimited" },
        "500": { "$ref": "#/components/responses/InternalError" }
    })
}

fn policy_list_responses() -> Value {
    json!({
        "200": {
            "description": "Effective policy snapshots and live usage counters.",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "array",
                        "items": { "$ref": "#/components/schemas/PolicySnapshot" }
                    }
                }
            }
        },
        "401": { "$ref": "#/components/responses/Unauthorized" },
        "500": { "$ref": "#/components/responses/InternalError" }
    })
}

fn policy_get_responses() -> Value {
    json!({
        "200": {
            "description": "Effective policy snapshot and live usage counters.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/PolicySnapshot" }
                }
            }
        },
        "401": { "$ref": "#/components/responses/Unauthorized" },
        "404": { "$ref": "#/components/responses/NotFound" },
        "500": { "$ref": "#/components/responses/InternalError" }
    })
}

fn admin_responses() -> Value {
    json!({
        "200": {
            "description": "Key enabled state was updated.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/AdminKeyResponse" }
                }
            }
        },
        "401": { "$ref": "#/components/responses/Unauthorized" },
        "404": { "$ref": "#/components/responses/NotFound" },
        "500": { "$ref": "#/components/responses/InternalError" }
    })
}

fn admin_policy_mutation_responses() -> Value {
    json!({
        "200": {
            "description": "Policy overlay was updated and effective policy was reloaded.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/PolicySnapshot" }
                }
            }
        },
        "400": { "$ref": "#/components/responses/BadRequest" },
        "401": { "$ref": "#/components/responses/Unauthorized" },
        "404": { "$ref": "#/components/responses/NotFound" },
        "500": { "$ref": "#/components/responses/InternalError" }
    })
}

fn key_policy_properties() -> Value {
    json!({
        "enabled": { "type": "boolean" },
        "max_signs_per_minute": { "type": ["integer", "null"], "minimum": 0 },
        "max_signs_per_hour": { "type": ["integer", "null"], "minimum": 0 },
        "max_signs_per_day": { "type": ["integer", "null"], "minimum": 0 },
        "daily_cap_lamports": { "type": ["string", "null"] },
        "per_tx_cap_lamports": { "type": ["string", "null"] },
        "allowed_programs": {
            "type": "array",
            "items": { "$ref": "#/components/schemas/AllowedProgram" }
        },
        "allowed_messages": {
            "type": "array",
            "items": { "$ref": "#/components/schemas/AllowedMessage" }
        },
        "allowed_recipients": {
            "type": "array",
            "items": { "$ref": "#/components/schemas/AllowedRecipient" }
        }
    })
}

fn key_label_parameter() -> Value {
    json!({
        "name": "label",
        "in": "path",
        "required": true,
        "schema": { "type": "string" },
        "description": "Configured key label."
    })
}

fn error_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" }
            }
        }
    })
}
