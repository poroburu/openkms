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
            { "name": "pairing" },
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
                    "summary": "Key pool capacity summary (alias of /pair/pool)",
                    "operationId": "listKeys",
                    "responses": {
                        "200": {
                            "description": "Per-chain pool counts without addresses by default.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/PoolSummary" }
                                }
                            }
                        }
                    }
                }
            },
            "/pair/pool": {
                "get": {
                    "tags": ["pairing"],
                    "summary": "Key pool capacity for pairing",
                    "operationId": "pairPool",
                    "responses": {
                        "200": {
                            "description": "Pool summary; optional key list when reveal_addresses is enabled.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/PoolSummary" }
                                }
                            }
                        }
                    }
                }
            },
            "/pair/request": {
                "post": {
                    "tags": ["pairing"],
                    "summary": "Request client-to-key pairing",
                    "operationId": "pairRequest",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/PairRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Pending request created.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/PairRequestResponse" }
                                }
                            }
                        },
                        "409": { "$ref": "#/components/responses/Conflict" }
                    }
                }
            },
            "/admin/pair/pending": {
                "get": {
                    "tags": ["admin", "pairing"],
                    "summary": "List pending pairing requests",
                    "operationId": "adminListPendingPair",
                    "security": [{ "adminBearer": [] }],
                    "responses": {
                        "200": {
                            "description": "Pending requests.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": { "$ref": "#/components/schemas/PendingPairRequest" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/admin/pair": {
                "get": {
                    "tags": ["admin", "pairing"],
                    "summary": "List active pairings",
                    "operationId": "adminListPair",
                    "security": [{ "adminBearer": [] }],
                    "responses": {
                        "200": {
                            "description": "Active pairings (no secrets).",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": { "$ref": "#/components/schemas/ActivePairing" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/admin/pair/pool": {
                "get": {
                    "tags": ["admin", "pairing"],
                    "summary": "Full key pool with addresses",
                    "operationId": "adminPairPool",
                    "security": [{ "adminBearer": [] }],
                    "responses": {
                        "200": {
                            "description": "Pool summary with per-key allocatable state and addresses.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/PoolSummary" }
                                }
                            }
                        }
                    }
                }
            },
            "/admin/pair/{id}/approve": {
                "post": {
                    "tags": ["admin", "pairing"],
                    "summary": "Approve a pairing request",
                    "operationId": "adminApprovePair",
                    "security": [{ "adminBearer": [] }],
                    "parameters": [pair_id_parameter()],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/PairApproveRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Pairing approved; bearer token returned once.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/PairApproveResponse" }
                                }
                            }
                        },
                        "503": { "$ref": "#/components/responses/ServiceUnavailable" }
                    }
                }
            },
            "/admin/pair/{id}/reject": {
                "post": {
                    "tags": ["admin", "pairing"],
                    "summary": "Reject a pending pairing request",
                    "operationId": "adminRejectPair",
                    "security": [{ "adminBearer": [] }],
                    "parameters": [pair_id_parameter()],
                    "responses": admin_responses()
                }
            },
            "/admin/pair/{id}": {
                "delete": {
                    "tags": ["admin", "pairing"],
                    "summary": "Revoke an active pairing",
                    "operationId": "adminRevokePair",
                    "security": [{ "adminBearer": [] }],
                    "parameters": [pair_id_parameter()],
                    "responses": admin_responses()
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
                    "description": "Per-client pairing token issued on admin approve (scoped to one key label)."
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
                "PolicySnapshot": {
                    "type": "object",
                    "required": ["label", "chain", "address", "object_id", "derivation_path", "effective_enabled", "policy", "runtime"],
                    "properties": {
                        "label": { "type": "string" },
                        "chain": {
                            "type": "string",
                            "enum": ["solana", "cosmos", "unknown"]
                        },
                        "address": { "type": "string" },
                        "object_id": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 65535
                        },
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
                "PoolSummary": {
                    "type": "object",
                    "required": ["chains"],
                    "properties": {
                        "chains": {
                            "type": "object",
                            "additionalProperties": { "$ref": "#/components/schemas/ChainPoolStats" }
                        },
                        "keys": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/PoolKeyEntry" }
                        }
                    }
                },
                "ChainPoolStats": {
                    "type": "object",
                    "required": ["configured", "allocatable", "paired", "reserved", "can_allocate"],
                    "properties": {
                        "configured": { "type": "integer" },
                        "allocatable": { "type": "integer" },
                        "paired": { "type": "integer" },
                        "reserved": { "type": "integer" },
                        "can_allocate": { "type": "boolean" }
                    }
                },
                "PoolKeyEntry": {
                    "type": "object",
                    "required": ["label", "chain", "allocatable"],
                    "properties": {
                        "label": { "type": "string" },
                        "chain": { "type": "string" },
                        "allocatable": { "type": "boolean" },
                        "address": { "type": "string" }
                    }
                },
                "PairRequest": {
                    "type": "object",
                    "required": ["client_id"],
                    "properties": {
                        "client_id": { "type": "string" },
                        "label": { "type": "string" },
                        "chain": { "type": "string" },
                        "pick": { "type": "string", "enum": ["most", "least", "random"] },
                        "asset": { "$ref": "#/components/schemas/PairAsset" },
                        "display_name": { "type": "string" },
                        "bearer": {
                            "type": "string",
                            "description": "Optional client-generated bearer (okms_ + 64 hex). Hashed at ingest; omit for server-mint on approve."
                        }
                    }
                },
                "PairAsset": {
                    "type": "object",
                    "required": ["kind"],
                    "properties": {
                        "kind": { "type": "string", "enum": ["native", "spl", "denom"] },
                        "mint": { "type": "string" },
                        "denom": { "type": "string" }
                    }
                },
                "PairRequestResponse": {
                    "type": "object",
                    "required": ["request_id", "status", "expires_at"],
                    "properties": {
                        "request_id": { "type": "string" },
                        "status": { "type": "string" },
                        "expires_at": { "type": "integer" }
                    }
                },
                "PendingPairRequest": {
                    "type": "object",
                    "required": ["id", "client_id", "request_kind", "requested_at", "expires_at"],
                    "properties": {
                        "id": { "type": "string" },
                        "client_id": { "type": "string" },
                        "request_kind": { "type": "string", "enum": ["labeled", "auto"] },
                        "label": { "type": ["string", "null"] },
                        "chain": { "type": ["string", "null"] },
                        "pick": { "type": "string", "enum": ["most", "least", "random"] },
                        "asset": { "$ref": "#/components/schemas/PairAsset" },
                        "display_name": { "type": ["string", "null"] },
                        "requested_at": { "type": "integer" },
                        "expires_at": { "type": "integer" }
                    }
                },
                "ActivePairing": {
                    "type": "object",
                    "required": ["id", "client_id", "label", "paired_at"],
                    "properties": {
                        "id": { "type": "string" },
                        "client_id": { "type": "string" },
                        "label": { "type": "string" },
                        "paired_at": { "type": "integer" },
                        "revoked_at": { "type": ["integer", "null"] }
                    }
                },
                "PairApproveRequest": {
                    "type": "object",
                    "properties": {
                        "label": {
                            "type": "string",
                            "description": "Override label for auto requests."
                        }
                    }
                },
                "PairApproveResponse": {
                    "type": "object",
                    "required": ["pairing_id", "client_id", "label", "bearer_source"],
                    "properties": {
                        "pairing_id": { "type": "string" },
                        "client_id": { "type": "string" },
                        "label": { "type": "string" },
                        "pick": { "type": "string", "enum": ["most", "least", "random"] },
                        "token": {
                            "type": "string",
                            "description": "Present only when bearer_source is server (minted on approve)."
                        },
                        "bearer_source": {
                            "type": "string",
                            "enum": ["server", "client"]
                        }
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
                "Conflict": error_response("Pool exhausted or label already paired."),
                "RateLimited": error_response("Rate-limit policy denied the request."),
                "ServiceUnavailable": error_response("Balance RPC unavailable for most/least pick."),
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

fn pair_id_parameter() -> Value {
    json!({
        "name": "id",
        "in": "path",
        "required": true,
        "schema": { "type": "string" },
        "description": "Pending request id or active pairing id."
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
