-- Drop `settings.registration.captcha` from stored tenant settings.
--
-- The console's "CAPTCHA on registration" toggle wrote that member, but the
-- server only ever read `settings.captcha.on_registration`, so the toggle did
-- nothing. The member is gone from the model; settings documents tolerate
-- unknown members, so leaving it would be harmless, but it would keep
-- suggesting a setting that does not exist. A tenant that switched it on
-- asked for a CAPTCHA on registration: that intent is carried over to the
-- real setting before the member is dropped.
UPDATE tenants
SET settings = jsonb_set(
        settings,
        '{captcha}',
        COALESCE(settings -> 'captcha', '{}'::jsonb) || '{"on_registration": true}'::jsonb
    )
WHERE settings -> 'registration' ->> 'captcha' = 'true';

UPDATE tenants
SET settings = settings #- '{registration,captcha}'
WHERE settings -> 'registration' ? 'captcha';
