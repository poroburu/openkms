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
                    "required": ["status", "hsm_up"],
                    "properties": {
                        "status": {
                            "type": "string",
                            "const": "ok"
                        },
                        "hsm_up": {
                            "type": ["boolean", "null"],
                            "description": "Null on the first response after process start; boolean thereafter."
                        }
                    }
                },
                "KeySummary": {
                    "type": "object",
                    "required": ["label", "chain", "address", "enabled", "object_id", "derivation_path"],
                    "properties": {
                        "label": { "type": "string" },
                        "chain": {
                            "type": "string",
                            "enum": ["solana", "cosmos", "unknown"]
                        },
                        "address": { "type": "string" },
                        "enabled": { "type": "boolean" },
                        "object_id": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 65535
                        },
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
