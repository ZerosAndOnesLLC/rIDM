//! Namespace and algorithm identifiers (SAML 2.0 Core, XML-DSig 1.1,
//! XML-Enc 1.1).

pub const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
pub const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
pub const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
pub const XS: &str = "http://www.w3.org/2001/XMLSchema";

pub const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

pub const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

pub const ATTRNAME_BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
pub const ATTRNAME_URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
pub const ATTRNAME_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

pub const AC_PASSWORD_PROTECTED: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
pub const AC_KERBEROS: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";
pub const AC_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
/// REFEDS MFA profile: what research and enterprise SPs ask for when they
/// want a second factor.
pub const AC_REFEDS_MFA: &str = "https://refeds.org/profile/mfa";
/// Microsoft's name for the same (Entra ID / ADFS federations).
pub const AC_MS_MULTIPLE_AUTHN: &str = "http://schemas.microsoft.com/claims/multipleauthn";

pub mod status {
    pub const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
    pub const REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
    pub const RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    pub const VERSION_MISMATCH: &str = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
    pub const AUTHN_FAILED: &str = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
    pub const INVALID_NAMEID_POLICY: &str =
        "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";
    pub const NO_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
    pub const NO_PASSIVE: &str = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
    pub const REQUEST_DENIED: &str = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
    pub const UNSUPPORTED_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
    pub const PARTIAL_LOGOUT: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
}

pub mod nameid {
    pub const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    pub const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    pub const EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    pub const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
}

pub mod alg {
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    pub const EXC_C14N_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
    pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
    pub const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

    pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    pub const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    pub const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

    pub const AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
    pub const AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    pub const AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    pub const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
    pub const RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    pub const RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
    pub const MGF1_SHA1: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha1";
    pub const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";

    pub const ENC_ELEMENT: &str = "http://www.w3.org/2001/04/xmlenc#Element";
}
