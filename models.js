const {Model,DataTypes,Sequelize} = require('sequelize')

const sequelize = new Sequelize('sqlite:./db.sql')

class User extends Model{}

User.init({
    username: DataTypes.STRING,
    password: DataTypes.STRING
},{sequelize:sequelize})

module.exports = { User , sequelize}
