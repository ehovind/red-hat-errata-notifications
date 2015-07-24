create table erratas (
    advisory    TEXT        NOT NULL primary key,
    synopsis    TEST        NOT NULL,
    cvss2       REAL,
    date        TIMESTAMP   NOT NULL
);
