mod apps;
mod contact;
mod data;
mod devices;
mod me;
mod mfa;
mod password;
mod profile;
mod sessions;

pub use apps::apps_router;
pub use contact::contact_router;
pub use data::data_router;
pub use devices::devices_router;
pub use me::me_router;
pub use mfa::mfa_router;
pub use password::password_router;
pub use profile::profile_router;
pub use sessions::sessions_router;
