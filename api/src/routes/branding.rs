//! Public, cacheable description of a tenant for the end-user pages: name,
//! theme, links, locales and which sign-in options exist. Nothing here is
//! secret; it is what any visitor of the login page would see anyway.

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;

use crate::middleware::TenantCtx;
use crate::models::{Branding, LocaleSettings};
use crate::services::locale;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/branding", get(branding))
}

#[derive(Debug, Serialize)]
pub struct PublicTenant<'a> {
    pub slug: &'a str,
    pub display_name: &'a str,
    pub branding: &'a Branding,
    pub locale: PublicLocale,
    /// First-factor methods the tenant offers.
    pub methods: Vec<&'static str>,
    pub registration: PublicRegistration<'a>,
}

#[derive(Debug, Serialize)]
pub struct PublicLocale {
    pub default: String,
    pub supported: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PublicRegistration<'a> {
    pub enabled: bool,
    pub terms_url: Option<&'a str>,
    pub privacy_url: Option<&'a str>,
}

pub fn public_locale(settings: &LocaleSettings) -> PublicLocale {
    let supported = locale::supported_of(settings);
    PublicLocale {
        default: locale::negotiate(&[], None, settings),
        supported,
    }
}

async fn branding(tenant: TenantCtx) -> Response {
    let t = &tenant.tenant;
    let s = &t.settings;
    let mut methods = vec![];
    if s.auth.password {
        methods.push("password");
    }
    if s.auth.magic_link {
        methods.push("magic_link");
    }
    if s.auth.email_otp {
        methods.push("email_otp");
    }
    if s.auth.sms_otp {
        methods.push("sms_otp");
    }
    if s.auth.passkey {
        methods.push("passkey");
    }
    let body = PublicTenant {
        slug: &t.slug,
        display_name: &t.display_name,
        branding: &s.branding,
        locale: public_locale(&s.locale),
        methods,
        registration: PublicRegistration {
            enabled: s.registration.enabled,
            terms_url: s.registration.terms_url.as_deref(),
            privacy_url: s.registration.privacy_url.as_deref(),
        },
    };
    let mut res = axum::Json(body).into_response();
    res.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    res
}
