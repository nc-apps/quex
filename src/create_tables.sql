BEGIN;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email_address TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_usability_score_surveys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS net_promoter_score_surveys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS attrakdiff_surveys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS system_usability_score_responses (
    id TEXT PRIMARY KEY,
    survey_id INTEGER NOT NULL,
    answer_1 INTEGER NOT NULL,
    answer_2 INTEGER NOT NULL,
    answer_3 INTEGER NOT NULL,
    answer_4 INTEGER NOT NULL,
    answer_5 INTEGER NOT NULL,
    answer_6 INTEGER NOT NULL,
    answer_7 INTEGER NOT NULL,
    answer_8 INTEGER NOT NULL,
    answer_9 INTEGER NOT NULL,
    answer_10 INTEGER NOT NULL,
    FOREIGN KEY (survey_id) REFERENCES system_usability_score_surveys(id)
);

CREATE TABLE IF NOT EXISTS net_promoter_score_responses (
    id TEXT PRIMARY KEY,
    survey_id INTEGER NOT NULL,
    answer_1 INTEGER NOT NULL,
    answer_2 TEXT,
    FOREIGN KEY(survey_id) REFERENCES net_promoter_score_surveys(id)
);

CREATE TABLE IF NOT EXISTS attrakdiff_responses (
    id TEXT PRIMARY KEY,
    survey_id INTEGER NOT NULL,
    answer_1 INTEGER NOT NULL,
    answer_2 INTEGER NOT NULL,
    answer_3 INTEGER NOT NULL,
    answer_4 INTEGER NOT NULL,
    answer_5 INTEGER NOT NULL,
    answer_6 INTEGER NOT NULL,
    answer_7 INTEGER NOT NULL,
    answer_8 INTEGER NOT NULL,
    answer_9 INTEGER NOT NULL,
    answer_10 INTEGER NOT NULL,
    answer_11 INTEGER NOT NULL,
    answer_12 INTEGER NOT NULL,
    answer_13 INTEGER NOT NULL,
    answer_14 INTEGER NOT NULL,
    answer_15 INTEGER NOT NULL,
    answer_16 INTEGER NOT NULL,
    answer_17 INTEGER NOT NULL,
    answer_18 INTEGER NOT NULL,
    answer_19 INTEGER NOT NULL,
    answer_20 INTEGER NOT NULL,
    answer_21 INTEGER NOT NULL,
    answer_22 INTEGER NOT NULL,
    answer_23 INTEGER NOT NULL,
    answer_24 INTEGER NOT NULL,
    answer_25 INTEGER NOT NULL,
    answer_26 INTEGER NOT NULL,
    answer_27 INTEGER NOT NULL,
    answer_28 INTEGER NOT NULL,
    FOREIGN KEY(survey_id) REFERENCES attrakdiff_surveys(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at_utc INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS signin_attempts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at_utc INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

END;
