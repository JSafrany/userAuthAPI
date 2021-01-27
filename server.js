const {sequelize, User} = require('./models')
const express = require('express')
const bcrypt = require('bcrypt')
const session = require('express-session')
const swaggerUi = require('swagger-ui-express')
const YAML = require('js-yaml')
const fs = require('fs')
const docs = YAML.load(fs.readFileSync('./authApi.yaml').toString())
const swaggerDocs = require('swagger-jsdoc')({
    swaggerDefinition: docs,
    apis: ['./server.js']
})

const app = express()

const sessionSettings = {
    secret: 'this is a secret',
    resave: false,
    saveUninitialized: true
}

class AuthSession {
    static lookup = {}

    constructor(id){
        this.loggedInAs = null
        AuthSession.lookup[id] = this
    }
    login(userId) {
        this.loggedInAs = userId
        return this.loggedInAs
    }
    logout() {
        this.loggedInAs = null
        return this.loggedInAs
    }
}

//sees if an AuthSession exists, if not makes one
function authSeshLookup(req,res,next){
    AuthSession.lookup[req.session.id] = AuthSession.lookup[req.session.id] || new AuthSession(req.session.id)
    next()
}

//decodes base 64 encoded string
function atob(b64String){
    let buff = new Buffer.from(b64String,'base64')
    return buff.toString()
}

//takes the username and password from the Auth header and sets them to res.locals to be
//used in other places
function getUserAndPass(req,res,next){
    console.log('in the thing')
    if (!req.headers.authorization){
        res.status(403).send()
        return
    }
    try{
        let authUserPass = req.headers.authorization
        var method
        [method, authUserPass] = authUserPass.split(" ")
        if (method !== 'Basic'){
            res.status(400).send()
        }
        const [username, password] = atob(authUserPass).split(':')
        res.locals.username = username
        res.locals.password = password
        return next()
    }
    catch(err){
        console.log(err)
        res.status(403).send()
        return
    }
}

//takes a userID and a username and password and checks that the given password and username
//in the database matches the ones passed to the function
async function checkAuth(userId, username, password){
    user = await User.findByPk(userId)
    if (user.username != username || ! await bcrypt.compare(password,user.password)){
        console.log('failedAuth')
        return false
    }
    else {
        console.log('passedAuth')
        return true
    }
}

//takes a potential username and sees if it exists in the database
async function doesUsernameExist(username1){
    const existingUser = await User.findAll({where:{username:username1}})
    console.log(existingUser)
    if (existingUser.length > 0 ){
        return true
    }
    return false
}

app.use(session(sessionSettings),express.json(),authSeshLookup)

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, {explorer: true}))

/**
 * @swagger
 * /login:
 *  post:
 *    summary: logs in as an existing user
 *    parameters:
 *      - name: Authorization
 *        in: header
 *        required: true
 *        description: username and password encoded into basicAuth
 *    responses:
 *      '200':
 *        description: OK. user has been logged in. The user will now be logged in and have access to the things for the rest of this session.
 *      '403':
 *        description: Unauthorized. user was unseccessful in logging in
 *
 */

app.get('/login',getUserAndPass,async (req,res)=>{
    users = await User.findAll({where:{username:res.locals.username}})
    if (await checkAuth(users[0].id,res.locals.username,res.locals.password)){
        console.log(req.session.id)
        AuthSession.lookup[req.session.id].login(users[0].id)
        console.log(AuthSession.lookup[req.session.id].loggedInAs)
        res.status(200).send()
        console.log('sucessful login')

        return
    }
    res.status(401).send()
    return
})


/**
 * @swagger
 * /logout:
 *  get:
 *      summary: logs out a logged in user
 *      responses:
 *          '200':
 *              description: OK. regardless of your previous state of logged-in-ness you are now logged out.
 *
 */

app.get('/logout',(req,res) =>{
    AuthSession.lookup[req.session.id].logout()
    res.status(200).send()
    console.log(AuthSession.lookup[req.session.id])
})

/**
 * @swagger
 * /users:
 *  get:
 *      summary: returns all the users that exist in the database with their username and hashed password
 *      responses:
 *          '200':
 *              description: successfully sent all the data. don't do anything too malicious with it now, ya hear?
 *              $ref: '#/components/Users'
 *
 */

app.get('/users', async (req,res) =>{
    const users = await User.findAll()
    res.status(200).send(users)
})

/**
 * @swagger
 * /users:
 *  post:
 *      summary: creates a user and puts them into the database
 *      requestBody:
 *          content:
 *              'application/json':
 *                  schema:
 *                      properties:
 *                          username:
 *                              type: string
 *                          password:
 *                              type: string
 *                      required:
 *                          - username
 *                          - password
 *      responses:
 *          '201':
 *              description: successfully created user
 *          '400':
 *              description: Body didn't have required fields or had additional fields
 *          '409':
 *              description: username already exists, so couldn't be used
 *          '415':
 *              description: body wasn't JSON
 *
 */

app.post('/users', async (req,res) =>{
    console.log("post attempt")
    if (Object.keys(req.body).length == 0){
        res.status(415).send({})
        return
    }
    if (!req.body.username || !req.body.password || Object.keys(req.body).length !== 2){
        res.status(400).send({})
        return
    }
    if (await doesUsernameExist(req.body.username) ){
        res.status(409).send({})
        return
    }
    const hashedPassword = await bcrypt.hash(req.body.password,10)
    console.log(hashedPassword)
    const user = await User.create({username:req.body.username,password:hashedPassword})
    res.status(201).send(user)
})

/**
 * @swagger
 * /users/:id:
 *  get:
 *      summary: the user's data from the database
 *      responses:
 *          '200':
 *              description: successfully sent all the data. don't do anything too malicious with it now, ya hear?
 *              $ref: '#/components/User'
 *          '403':
 *              description: forbidden. the logged in user isn't the same as the user they're trying to get
 *          '404':
 *              description: user not found
 */

app.get('/users/:id', async (req,res) =>{
    if (AuthSession.lookup[req.session.id].loggedInAs != req.params.id){
        res.status(403).send()
        return
    }
    const user = await User.findByPk(req.params.id)
    if (!user){
        res.status(404).send({})
        return
    }
    res.status(200).send(user)
    return
})

/**
 * @swagger
 * /users/:id:
 *  put:
 *      summary: edits a user
 *      requestBody:
 *          content:
 *              'application/json':
 *                  schema:
 *                      properties:
 *                          username:
 *                              type: string
 *                          password:
 *                              type: string
 *      responses:
 *          '200':
 *              description: successfully edited user
 *          '400':
 *              description: Body had fields that weren't username or password
 *          '403':
 *              description: current logged in user isn't editing their own profile
 *          '409':
 *              description: username already exists, so couldn't be used
 *          '415':
 *              description: body wasn't JSON
 *
 */

app.put('/users/:id',async (req,res) =>{
    if (AuthSession.lookup[req.session.id].loggedInAs != req.params.id){
        res.status(403).send()
        return
    }
    const user = await User.findByPk(req.params.id)
    if (!user){
        res.status(404).send({})
        return
    }

    if (Object.keys(req.body).length == 0){
        res.status(415).send({})
        return
    }
    if (! Object.keys(req.body).every(val => ['username','password'].includes(String(val)))){
        res.status(400).send({})
        return
    }

    if(req.body.username){
        if (await doesUsernameExist(req.body.username) ){
            res.status(409).send({})
            return
        }
        await user.update({username:req.body.username})
    }

    if(req.body.password){
        const hashedPassword = await bcrypt.hash(req.body.password,10)
        await user.update({password: hashedPassword})
    }

    res.status(200).send(user)
    return
})

/**
 * @swagger
 * /users/:id:
 *  delete:
 *      summary: deletes the user
 *      responses:
 *          '204':
 *              description: sucessfully deleted the user
 *          '403':
 *              description: the user is not logged in, or is logged in as someone other than the user they are trying to delete
 *          '404':
 *              description: the user that is trying to be deleted doesn't exist
 */

app.delete('/users/:id',async (req,res)=>{
    if (AuthSession.lookup[req.session.id].loggedInAs != req.params.id){
        res.status(403).send()
        return
    }
    const user = await User.findByPk(req.params.id)
    if (!user){
        res.status(404).send({})
        return
    }
    user.destroy()
    res.status(204).send()
    return

})





app.listen(3000,()=>{
    sequelize.sync().then(console.log("ready"))
})
