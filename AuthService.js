// services/AuthService.js
const bcrypt = require("bcryptjs");

class AuthService
{
    constructor(userModel)
    {
        this.userModel = userModel;
    }

    async register(username, password)
    {
        const existing = await this.userModel.findByUsername(username);

        if (existing !== null)
        {
            throw new Error("Username already exists");
        }

        const passwordHash = await bcrypt.hash(password, 10);

        await this.userModel.save({ username, passwordHash });
    }

    async login(username, password)
    {
        const user = await this.userModel.findByUsername(username);

        if (user === null)
        {
            return false;
        }

        return bcrypt.compare(password, user.passwordHash);
    }
}

module.exports = AuthService;