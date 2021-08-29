CREATE DATABASE test

CREATE TABLE users (
  	id uuid PRIMARY KEY NOT NULL UNIQUE,
	username varchar NOT NULL,
  	email varchar NOT NULL UNIQUE,
  	password varchar NOT NULL
);