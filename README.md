
# User Authentication Server

## Get Started:

- Make sure mongodb and nodejs is installed in system.

- Run following command in root of this repository for installing required node-packages:
```
npm i
```


- For starting server, run following command in root of this repository:
```
node index.js
```

- Debugging Logs will be written in ./logs/info.log & printed on console.



## Tech Used:

 - Node js
 - JWT
 - Mongodb (mongoose)
 - bcrypt
 - Postman (for APIs)
 - Winston (for info.log)



## API Reference

 ### User Registeration:

```http
  POST localhost:3000/api/auth/register
```
Request Body
```
{
    "name": "Test User",
    "username": "testuser123",
    "age": "24",
    "password": "testuser",
    "bio": "Test Bio!"
}
```
Response Body
```
{
    "message": "User created Successfully.",
    "userInfo": {
      "name": "Test User",
      "username": "testuser123",
      "age": "24",
      "bio": "Test Bio!"
    }
}
```

 ### User Login:


Request Body
```
{
    "username": "testuser1",
    "password": "testuser"
}
```

#### Response Body
```
{
    "message": "Auth successful",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI......xWBrAAYoXTIJaAk"
}
```


 ### Get User Details:
Token required**
```http
  POST localhost:3000/api/users/details
```



#### Response Body
```
{
    "message": "User info fetched successfully.",
    "user": {
        "name": "Manish Rana Test 1",
        "username": "manish1",
        "bio": "My Bio!",
        "age": 24
    }
}
```


### Update User Details:

API update user specified field, allowed field to update name, username, bio, age, it will also gives if input username already in.

Auth-token required**
```http
  PUT localhost:3000/api/users/update
```


#### Request Body
```
{
    
    "name": "Manish Rana",
    "username": "manish1",
    "bio": "My Bio 2!",
    "age": 24
   
}
```
#### Response Body
```
{
    "message": "User info updated successfully.",
    "updatedUser": {
        "name": "Manish Rana",
        "username": "manish1",
        "bio": "My Bio 2!",
        "age": 24
    }
}
```



### Delete User Account:

API for deleting user account after certain grace period amount of time elapsed, in case user wants to prevent deletion of account then by using login API within grace period this acount deletion can be prevented.

For delting user account on its own after certain grace period, TTL index on expiresAt field is created (mongo feature).

There is 2 -3 mins delay in action of deletion by mongodb as noticed in testing, for larger grace period such as 24 hrs or 30days it will not much affect the concept but for testing purpose i used 3mins as grace period, so it will delete user document within 5-6 mins.

You can set GRACE_MINS env variable present in .env for higher duration.

Auth-token required**

```http
  DELETE localhost:3000/api/users/delete
```


#### Request Body
```
{ 
    "password": "testuser123"
}
```
#### Response Body
```
{
    "message": "There is a grace Period of 3 mins, i.e., account will be \\
                invalidated/delted after (in GMT timezone) Sun, 03 Dec 2023 08:46:01 GMT.\\
                In case you want to recover account try to login before grace period ends.",

    "gracePeriodEnds": 1701593161234
}
```


### User Logout:

Auth-token required**
```http
  POST localhost:3000/api/auth/logout
```

#### Response Body
```
{
    "message": "User logout success."
}
```

### User Password Reset:

```http
  PUT localhost:3000/api/users/update
```


#### With Auth-token:
Request Body
```
{
    
    "currentPassword": "testuser123",
    "newPassword": "testuser321"
   
}
```
Response Body
```
{
    "message": "Password updated successfully."
}
```

#### Without Auth-token:
Request Body
```
{
    "username": "testuser",
    "currentPassword": "testuser123",
    "newPassword": "testuser321"
   
}
```
Response Body
```
{
    "message": "Password updated successfully."
}
```




## Authors

- [@mannuR22](https://www.github.com/mannuR22)

