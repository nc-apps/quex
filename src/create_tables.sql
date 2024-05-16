CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_usability_score (
    id INTEGER PRIMARY KEY,
    answer_1 INTEGER NOT NULL,
    answer_2 INTEGER NOT NULL,
    answer_3 INTEGER NOT NULL,
    answer_4 INTEGER NOT NULL,
    answer_5 INTEGER NOT NULL,
    answer_6 INTEGER NOT NULL,
    answer_7 INTEGER NOT NULL,
    answer_8 INTEGER NOT NULL,
    answer_9 INTEGER NOT NULL,
    answer_10 INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS net_promoter_score (
    id INTEGER PRIMARY KEY,
    answer_1 INTEGER NOT NULL,
    answer_2 TEXT
);

CREATE TABLE IF NOT EXISTS attrakdiff (
    id INTEGER PRIMARY KEY,
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
    answer_28 INTEGER NOT NULL
);