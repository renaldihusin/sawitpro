/**
  This is the SQL script that will be used to initialize the database schema.
  We will evaluate you based on how well you design your database.
  1. How you design the tables.
  2. How you choose the data types and keys.
  3. How you name the fields.
  In this assignment we will use PostgreSQL as the database.
  */

-- Create a table to store user information
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    phone_number VARCHAR(20) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL
);

-- Insert a new user into the users table
INSERT INTO users (phone_number, full_name, password)
VALUES ('+6281234567890', 'Renaldi Husin', '$2a$10$6IkiMf');

-- Update user's full name by user ID
UPDATE users
SET full_name = 'Husin Renaldi'
WHERE user_id = 1;

-- Select user information by user ID
SELECT user_id, phone_number, full_name
FROM users
WHERE user_id = 1;

