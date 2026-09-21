-- Risk-based adaptive authentication (Phase 12.3): the history a sign-in is
-- judged against.
--
-- The signals themselves come from what rIDM already keeps — trusted devices
-- and session user agents for "new device", `login_attempts` for velocity —
-- except location, which nothing recorded until now. One row per user and
-- country holds where that user has signed in from before, so "new country"
-- is a lookup and "impossible travel" is the distance from the most recently
-- seen location over the time since it was seen.
--
-- Coordinates are optional: a deployment whose geo source only yields a
-- country (a CDN header) still gets new-country, and only loses travel.
--
-- Nothing populates this table unless a tenant turns the risk policy on, and
-- an empty history never raises a signal, which is what keeps a tenant that
-- enables the policy from step-ing up every user on their next sign-in.

CREATE TABLE user_login_locations (
    tenant_id     uuid        NOT NULL,
    user_id       uuid        NOT NULL,
    -- ISO 3166-1 alpha-2, upper case.
    country       text        NOT NULL,
    -- Of the most recent sign-in from this country, when the source knows them.
    latitude      double precision,
    longitude     double precision,
    logins        bigint      NOT NULL DEFAULT 1,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id, country),
    CONSTRAINT user_login_locations_country_format CHECK (country ~ '^[A-Z]{2}$'),
    CONSTRAINT user_login_locations_latitude_range
        CHECK (latitude IS NULL OR latitude BETWEEN -90 AND 90),
    CONSTRAINT user_login_locations_longitude_range
        CHECK (longitude IS NULL OR longitude BETWEEN -180 AND 180),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

-- "Where was this user last seen?" — the impossible-travel query, and the
-- ordering the account console lists locations in.
CREATE INDEX user_login_locations_recent_idx
    ON user_login_locations (tenant_id, user_id, last_seen_at DESC);

SELECT enable_tenant_rls('user_login_locations');
