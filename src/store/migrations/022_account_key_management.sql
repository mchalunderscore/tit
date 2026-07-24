ALTER TABLE ssh_login_approval
ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login'
CHECK (purpose IN ('login', 'account-key'));

ALTER TABLE ssh_login_approval
ADD COLUMN expected_account_id INTEGER REFERENCES account(id);

ALTER TABLE web_session
ADD COLUMN ssh_public_key_id INTEGER REFERENCES ssh_public_key(id);
