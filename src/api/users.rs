// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! `/v1/users/me` — return the authenticated caller's identity.

use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::UserToken;

/// Response for `GET /v1/users/me`.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserMeResponse {
    /// User identifier (from JWT `sub` claim).
    pub user_id: String,
    /// Role (admin, user, read_only).
    pub role: String,
}

/// Return the authenticated user's identity and role.
#[utoipa::path(
    get,
    path = "/v1/users/me",
    tag = "Users",
    summary = "Current user info",
    description = "Returns the authenticated user's identity and role from the JWT token.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "User info", body = UserMeResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_me(UserToken(token): UserToken) -> Json<UserMeResponse> {
    Json(UserMeResponse {
        user_id: token.sub,
        role: token.role,
    })
}
