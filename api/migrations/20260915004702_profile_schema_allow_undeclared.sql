-- 0003: profile schema flag for accepting attributes that are not declared.
ALTER TABLE user_profile_schema
    ADD COLUMN allow_undeclared boolean NOT NULL DEFAULT false;
