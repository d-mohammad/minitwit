insert into user (username, email, pw_hash) values ('testuser', 'testuser@email.com', 'password');
insert into user (username, email, pw_hash) values ('user1', 'user1@email.com', 'password');
insert into user (username, email, pw_hash) values ('user2', 'user2@email.com', 'password');
insert into user (username, email, pw_hash) values ('user3', 'user3@email.com', 'password');
insert into user (username, email, pw_hash) values ('user4', 'user4@email.com', 'password');

insert into message (author_id, text, pub_date) values(1, 'testUser-message1', 1);
insert into message (author_id, text, pub_date) values(2, 'user1-message1', 2);
insert into message (author_id, text, pub_date) values(1, 'testUser-message2', 3);
insert into message (author_id, text, pub_date) values(5, 'user4-message1', 4);
insert into message (author_id, text, pub_date) values(3, 'user2-message1', 5);
insert into message (author_id, text, pub_date) values(3, 'user2-message2', 6);
insert into message (author_id, text, pub_date) values(4, 'user3-message1', 7);
insert into message (author_id, text, pub_date) values(5, 'user4-message2', 8);

